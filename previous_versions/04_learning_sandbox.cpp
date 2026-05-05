#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <map>
#include <set>
#include <string>
#include <ctime>
#include <algorithm>
#include <vector>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// Connection state tracking
struct ConnectionInfo {
    time_t last_syn_time;
    uint16_t last_syn_port;
    std::set<uint16_t> scanned_ports;
    time_t first_syn_time;
    int stealth_hit_count;
};

std::map<std::string, ConnectionInfo> tracker;
std::set<std::string> blocked_ips;

void send_alert_to_python(std::string message) {
    int sock = 0;
    struct sockaddr_un serv_addr;
    const char* sock_path = "/tmp/ndr.sock";

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) return;

    serv_addr.sun_family = AF_UNIX;
    strcpy(serv_addr.sun_path, sock_path);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
        send(sock, message.c_str(), message.length(), 0);
    }
    close(sock);
}

void block_ip(std::string ip) {
    if (blocked_ips.count(ip)) return;

    std::string command = "iptables -A INPUT -s " + ip + " -j DROP";
    int result = system(command.c_str());
    if (result == 0) {
        std::cout << "[INFO] Zablokowano IP: " << ip << std::endl;
        blocked_ips.insert(ip);
    } else {
        std::cerr << "[ERROR] Nie można zablokować IP: " << ip << std::endl;
    }
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (pkthdr->len < 34) return; // Ethernet (14) + IP (20) minimum


    struct iphdr *ip = (struct iphdr *)(packet + 14);
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
    std::string ip_str(src_ip);

    if (ip->protocol == IPPROTO_TCP) {
        int ihl = ip->ihl * 4;
        // Ensure packet is long enough for TCP header
        if (pkthdr->len < 14 + ihl + 20) return;

        struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ihl);
        uint16_t d_port = ntohs(tcp->dest);
        time_t now = time(NULL);

        // Stealth Scan detection (SYN followed by RST)
        if (tcp->rst && tracker.count(ip_str)) {
            ConnectionInfo &info = tracker[ip_str];

            if (info.last_syn_time > 0 && (now - info.last_syn_time) <= 1) {
                info.stealth_hit_count++;
                std::cout << "[INFO] SYN->RST wzorzec od " << ip_str 
                          << " (licznik: " << info.stealth_hit_count << "/3)" << std::endl;
                
                if (info.stealth_hit_count >= 3) {
                    std::cout << "!!! [STEALTH] Wykryto powtarzalny wzorzec SYN->RST od: " << ip_str 
                              << " - PRAWDOPODOBNY NMAP -sS!" << std::endl;
                    info.stealth_hit_count = 0;
                    block_ip(ip_str);

                    std::string alert = "{\"type\": \"StealthScan\", \"ip\": \"" + ip_str + "\", \"msg\": \"Detected SYN->RST pattern\"}";
                    send_alert_to_python(alert);
                }
            }
        }

        // Port sweep detection (SYN accumulation)
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
            if (info.scanned_ports.size() > 5) {
                std::cout << "! [ALERT] Wykryto skanowanie portów od: " << ip_str 
                          << " (unikalne porty: " << info.scanned_ports.size() << " w 5s)" << std::endl;
                block_ip(ip_str);

                std::string alert = "{\"type\": \"PortScan\", \"ip\": \"" + ip_str + "\", \"msg\": \"Detected port sweep\"}";
                send_alert_to_python(alert);

                info.scanned_ports.clear(); 
            }
        }

        // DPI Module
        int ip_header_len = ihl;
        int tcp_header_len = tcp->doff * 4;

        // Extract payload
        int total_headers_size = 14 + ip_header_len + tcp_header_len;
        const u_char *payload = packet + total_headers_size;
        int payload_len = pkthdr->len - total_headers_size;

        if (payload_len > 0) {
            std::string data((const char*)payload, payload_len);
            std::string data_lower = data;
            std::transform(data_lower.begin(), data_lower.end(), data_lower.begin(), ::tolower);

            // Signatures to check
            const std::vector<std::string> signatures = {
                "union select", "drop table", "select * from",   // SQL Injection
                "etc/passwd", "bin/sh", "cmd.exe",               // OS Commands / Traversal
                "' or '1'='1", "' or 1=1"                        // Auth Bypass
            };

            for (const auto& sig : signatures) {
                if (data_lower.find(sig) != std::string::npos) {
                    std::cout << "!!! [DPI ALERT] Detected signature: " << sig << " from: " << ip_str << std::endl;
                    block_ip(ip_str);

                    std::string alert = "{\"type\": \"DPI\", \"ip\": \"" + ip_str + "\", \"msg\": \"Detected SQLi\"}";
                    send_alert_to_python(alert);

                    break; // One hit is enough to block
                }
            }
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("lo", 65535, 1, 1000, errbuf);

    if (!handle) return 1;

    std::cout << "Sensor NDR: Monitorowanie wzorców skanowania..." << std::endl;
    pcap_loop(handle, 0, packet_handler, NULL);
    
    pcap_close(handle);
    return 0;
}