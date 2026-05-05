#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <map>
#include <set>
#include <string>
#include <ctime>
#include <algorithm>
#include <vector>
#include <sstream>
#include <iomanip>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstring>

// ============== CONFIGURATION ==============
const std::string SOCK_PATH = "/tmp/ndr.sock";
const std::set<std::string> WHITELIST = {
    "127.0.0.1",           // localhost
    "::1",                 // localhost IPv6
    "192.168.1.1",         // typical gateway
    "192.168.0.1"          // typical gateway
};

const int PORT_SCAN_THRESHOLD = 5;           // porty w ciągu 5s
const int STEALTH_PATTERN_THRESHOLD = 3;     // SYN->RST powtórzenia
const int STEALTH_TIME_WINDOW = 1;           // okno czasowe (sekundy)

// ============== ALERT SEVERITY ==============
enum AlertSeverity {
    INFO = 1,
    WARNING = 2,
    CRITICAL = 3
};

// ============== CONNECTION TRACKING ==============
struct ConnectionInfo {
    time_t last_syn_time;
    uint16_t last_syn_port;
    std::set<uint16_t> scanned_ports;
    time_t first_syn_time;
    int stealth_hit_count;
    int attack_count; // licznik ataków do eskalacji
    time_t last_attack_time;
};

std::map<std::string, ConnectionInfo> tracker;
std::set<std::string> blocked_ips;

// ============== UTILITY FUNCTIONS ==============

// Get current timestamp in ISO 8601 format
std::string get_timestamp() {
    time_t now = time(0);
    struct tm *timeinfo = localtime(&now);
    char buffer[25];
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", timeinfo);
    return std::string(buffer);
}

// URL decode: convert %20 -> space, etc.
std::string url_decode(const std::string& encoded) {
    std::string decoded;
    for (size_t i = 0; i < encoded.length(); ++i) {
        if (encoded[i] == '%' && i + 2 < encoded.length()) {
            int hex = 0;
            sscanf(encoded.c_str() + i + 1, "%2x", &hex);
            decoded += static_cast<char>(hex);
            i += 2;
        } else if (encoded[i] == '+') {
            decoded += ' ';
        } else {
            decoded += encoded[i];
        }
    }
    return decoded;
}

// Convert severity enum to string
std::string severity_to_string(AlertSeverity sev) {
    switch(sev) {
        case INFO: return "INFO";
        case WARNING: return "WARNING";
        case CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

// Build rich JSON alert
std::string build_json_alert(
    const std::string& alert_type,
    const std::string& src_ip,
    uint16_t dest_port,
    const std::string& protocol,
    const std::string& signature,
    AlertSeverity severity,
    const std::string& additional_data = ""
) {
    std::ostringstream json;
    json << "{"
         << "\"timestamp\": \"" << get_timestamp() << "\", "
         << "\"type\": \"" << alert_type << "\", "
         << "\"severity\": " << static_cast<int>(severity) << ", "
         << "\"severity_name\": \"" << severity_to_string(severity) << "\", "
         << "\"src_ip\": \"" << src_ip << "\", "
         << "\"dest_port\": " << dest_port << ", "
         << "\"protocol\": \"" << protocol << "\", "
         << "\"signature\": \"" << signature << "\"";
    
    if (!additional_data.empty()) {
        json << ", " << additional_data;
    }
    
    json << "}";
    return json.str();
}

// Send alert via Unix socket
void send_alert_to_python(const std::string& json_message) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "[ERROR] Nie można utworzyć socketu" << std::endl;
        return;
    }

    struct sockaddr_un serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sun_family = AF_UNIX;
    strncpy(serv_addr.sun_path, SOCK_PATH.c_str(), sizeof(serv_addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
        ssize_t bytes_sent = send(sock, json_message.c_str(), json_message.length(), 0);
        if (bytes_sent > 0) {
            std::cout << "[SENT] Alert wysłany do Pythona (" << bytes_sent << " bytes)" << std::endl;
        }
    } else {
        std::cerr << "[ERROR] Nie można połączyć z Pythonem" << std::endl;
    }
    close(sock);
}

// Block IP using iptables
void block_ip(const std::string& ip) {
    // Check whitelist
    if (WHITELIST.count(ip)) {
        std::cout << "[SKIP] IP " << ip << " jest na whiteliście" << std::endl;
        return;
    }

    if (blocked_ips.count(ip)) {
        std::cout << "[INFO] IP " << ip << " już zablokowany" << std::endl;
        return;
    }

    std::string command = "iptables -A INPUT -s " + ip + " -j DROP";
    int result = system(command.c_str());
    if (result == 0) {
        std::cout << "[BLOCK] Zablokowano IP: " << ip << std::endl;
        blocked_ips.insert(ip);
    } else {
        std::cerr << "[ERROR] Nie można zablokować IP: " << ip << std::endl;
    }
}

// ============== PACKET HANDLER ==============

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Minimum Ethernet (14) + IP (20) headers
    if (pkthdr->len < 34) return;

    struct iphdr *ip = (struct iphdr *)(packet + 14);
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
    std::string ip_str(src_ip);

    // Check whitelist
    if (WHITELIST.count(ip_str)) {
        return;
    }

    if (ip->protocol == IPPROTO_TCP) {
        int ihl = ip->ihl * 4;
        if (pkthdr->len < 14 + ihl + 20) return;

        struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ihl);
        uint16_t d_port = ntohs(tcp->dest);
        time_t now = time(NULL);

        // ===== STEALTH SCAN DETECTION =====
        if (tcp->rst && tracker.count(ip_str)) {
            ConnectionInfo &info = tracker[ip_str];

            if (info.last_syn_time > 0 && (now - info.last_syn_time) <= STEALTH_TIME_WINDOW) {
                info.stealth_hit_count++;
                std::cout << "[STEALTH] SYN->RST pattern od " << ip_str 
                          << " (licznik: " << info.stealth_hit_count << "/" << STEALTH_PATTERN_THRESHOLD << ")" << std::endl;
                
                if (info.stealth_hit_count >= STEALTH_PATTERN_THRESHOLD) {
                    std::cout << "!!! [CRITICAL] Stealth scan (nmap -sS) od: " << ip_str << std::endl;
                    
                    std::string json = build_json_alert(
                        "StealthScan",
                        ip_str,
                        d_port,
                        "TCP",
                        "SYN->RST_pattern_repeated",
                        CRITICAL,
                        "\"pattern_count\": " + std::to_string(info.stealth_hit_count)
                    );
                    
                    send_alert_to_python(json);
                    block_ip(ip_str);
                    info.stealth_hit_count = 0;
                }
            }
        }

        // ===== PORT SCAN DETECTION =====
        if (tcp->syn && !tcp->ack) {
            ConnectionInfo &info = tracker[ip_str];

            // Reset window after 5s of inactivity
            if (info.first_syn_time == 0 || (now - info.first_syn_time) > 5) {
                info.first_syn_time = now;
                info.scanned_ports.clear();
            }

            info.last_syn_time = now;
            info.last_syn_port = d_port;
            info.scanned_ports.insert(d_port);

            // Trigger alert if threshold exceeded
            if (info.scanned_ports.size() > PORT_SCAN_THRESHOLD) {
                std::cout << "! [WARNING] Port scan od: " << ip_str 
                          << " (unikalne porty: " << info.scanned_ports.size() << " w 5s)" << std::endl;
                
                std::ostringstream ports_str;
                for (auto p : info.scanned_ports) {
                    ports_str << p << ",";
                }
                std::string ports = ports_str.str();
                if (!ports.empty()) ports.pop_back();

                std::string json = build_json_alert(
                    "PortScan",
                    ip_str,
                    d_port,
                    "TCP",
                    "port_sweep_detected",
                    WARNING,
                    "\"scanned_port_count\": " + std::to_string(info.scanned_ports.size()) + 
                    ", \"ports\": \"" + ports + "\""
                );
                
                send_alert_to_python(json);
                block_ip(ip_str);
                info.scanned_ports.clear();
            }
        }

        // ===== DPI MODULE (Payload Inspection) =====
        int ip_header_len = ihl;
        int tcp_header_len = tcp->doff * 4;
        int total_headers_size = 14 + ip_header_len + tcp_header_len;

        if (total_headers_size < pkthdr->len) {
            const u_char *payload = packet + total_headers_size;
            int payload_len = pkthdr->len - total_headers_size;

            if (payload_len > 0) {
                std::string data((const char*)payload, payload_len);
                // URL decode the payload
                std::string decoded_data = url_decode(data);
                std::string data_lower = decoded_data;
                std::transform(data_lower.begin(), data_lower.end(), data_lower.begin(), ::tolower);

                // Signatures to check
                const std::vector<std::pair<std::string, std::string>> signatures = {
                    {"union select", "SQL_injection_union"},
                    {"drop table", "SQL_injection_drop"},
                    {"select * from", "SQL_injection_select"},
                    {"' or '1'='1", "SQL_auth_bypass"},
                    {"' or 1=1", "SQL_auth_bypass"},
                    {"/etc/passwd", "Path_traversal"},
                    {"/bin/sh", "Command_injection"},
                    {"cmd.exe", "Windows_command_injection"}
                };

                for (const auto& sig_pair : signatures) {
                    const std::string& sig = sig_pair.first;
                    const std::string& sig_name = sig_pair.second;
                    
                    if (data_lower.find(sig) != std::string::npos) {
                        std::cout << "!!! [CRITICAL] DPI Alert: " << sig_name << " from: " << ip_str << std::endl;
                        
                        std::string json = build_json_alert(
                            "DPI_Attack",
                            ip_str,
                            d_port,
                            "TCP",
                            sig_name,
                            CRITICAL,
                            "\"matched_signature\": \"" + sig + "\""
                        );
                        
                        send_alert_to_python(json);
                        block_ip(ip_str);
                        break;
                    }
                }
            }
        }
    }
    // UDP and ICMP can be added here in the future
}

// ============== MAIN ==============

int main() {
    std::cout << "================================" << std::endl;
    std::cout << "  NDR System v6 - Sensor" << std::endl;
    std::cout << "  Rich JSON + Whitelist + DPI" << std::endl;
    std::cout << "================================" << std::endl << std::endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("lo", 65535, 1, 1000, errbuf);

    if (!handle) {
        std::cerr << "[ERROR] Nie można otworzyć interfejsu: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "[*] Sensor NDR: Monitorowanie ruchu sieciowego..." << std::endl;
    std::cout << "[*] Whitelist: 127.0.0.1, ::1, 192.168.*.* (gateway)" << std::endl;
    std::cout << "[*] Oczekiwanie na połączenie z Pythonem na " << SOCK_PATH << std::endl << std::endl;

    pcap_loop(handle, 0, packet_handler, NULL);
    
    pcap_close(handle);
    return 0;
}
