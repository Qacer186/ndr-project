#include "../include/Detector.hpp"
#include "../include/Emitter.hpp"
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

namespace NDR {

Detector* Detector::instance = nullptr;

// ============== UTILITY FUNCTIONS ==============

std::string Detector::get_timestamp() {
    time_t now = time(0);
    struct tm *timeinfo = localtime(&now);
    char buffer[25];
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", timeinfo);
    return std::string(buffer);
}

std::string Detector::url_decode(const std::string& encoded) {
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

std::string Detector::severity_to_string(Config::AlertSeverity sev) {
    switch(sev) {
        case Config::INFO: return "INFO";
        case Config::WARNING: return "WARNING";
        case Config::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

std::string Detector::build_json_alert(
    const std::string& alert_type,
    const std::string& src_ip,
    uint16_t dest_port,
    const std::string& protocol,
    const std::string& category,
    const std::string& signature,
    Config::AlertSeverity severity,
    const std::string& additional_data
) {
    std::ostringstream json;
    json << "{"
         << "\"timestamp\": \"" << get_timestamp() << "\", "
         << "\"type\": \"" << alert_type << "\", "
         << "\"category\": \"" << category << "\", "
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

// ============== DETECTION METHODS ==============

void Detector::detect_dos(const std::string& ip) {
    time_t now = time(NULL);
    ConnectionInfo &info = tracker[ip];

    info.packet_count++;

    if (now - info.last_reset >= Config::DOS_TIME_WINDOW) {
        if (info.packet_count > Config::DOS_PACKET_THRESHOLD) {
            std::cout << "[DOS] " << ip << " (" << info.packet_count << " PPS)" << std::endl;
            
            std::string json = build_json_alert(
                "DoS_Attack",
                ip,
                0,
                "MIXED",
                "Rate_Limiting",
                "excessive_packets",
                Config::CRITICAL,
                "\"packets_per_second\": " + std::to_string(info.packet_count)
            );
            
            Emitter::getInstance()->send_alert(json);
            Emitter::getInstance()->block_ip(ip);
        }
        info.packet_count = 0;
        info.last_reset = now;
    }
}

void Detector::detect_stealth_scan(const std::string& ip, uint16_t d_port) {
    time_t now = time(NULL);
    ConnectionInfo &info = tracker[ip];

    if (info.last_syn_time > 0 && (now - info.last_syn_time) <= Config::STEALTH_TIME_WINDOW) {
        info.stealth_hit_count++;
        
        if (info.stealth_hit_count >= Config::STEALTH_PATTERN_THRESHOLD && !info.is_stealth_flagged) {
            std::cout << "[STEALTH] nmap -sS from " << ip << std::endl;
            
            std::string json = build_json_alert(
                "StealthScan",
                ip,
                d_port,
                "TCP",
                "Port_Scanning",
                "SYN_RST_pattern",
                Config::CRITICAL,
                "\"pattern_count\": " + std::to_string(info.stealth_hit_count)
            );
            
            Emitter::getInstance()->send_alert(json);
            Emitter::getInstance()->block_ip(ip);
            info.is_stealth_flagged = true;
        }
    }
}

void Detector::detect_port_scan(const std::string& ip, uint16_t d_port) {
    time_t now = time(NULL);
    ConnectionInfo &info = tracker[ip];

    // Reset window after 5s of inactivity
    if (info.first_syn_time == 0 || (now - info.first_syn_time) > 5) {
        info.first_syn_time = now;
        info.scanned_ports.clear();
    }

    info.scanned_ports.insert(d_port);

    // Trigger alert if threshold exceeded (but only once per IP)
    if (info.scanned_ports.size() > Config::PORT_SCAN_THRESHOLD && !info.is_stealth_flagged) {
        std::cout << "[SCAN] Port sweep from " << ip << " (" << info.scanned_ports.size() << " ports)" << std::endl;
        
        std::ostringstream ports_str;
        int count = 0;
        for (auto p : info.scanned_ports) {
            if (count++ < 10) ports_str << p << ",";
        }
        std::string ports = ports_str.str();
        if (!ports.empty()) ports.pop_back();

        std::string json = build_json_alert(
            "PortScan",
            ip,
            d_port,
            "TCP",
            "Port_Scanning",
            "port_sweep",
            Config::WARNING,
            "\"scanned_port_count\": " + std::to_string(info.scanned_ports.size()) + 
            ", \"sample_ports\": \"" + ports + "\""
        );
        
        Emitter::getInstance()->send_alert(json);
        Emitter::getInstance()->block_ip(ip);
        info.scanned_ports.clear();
    }
}

void Detector::detect_dpi(const u_char *payload, int payload_len, const std::string& ip, uint16_t d_port) {
    if (payload_len <= 0) return;

    std::string data((const char*)payload, payload_len);
    std::string decoded_data = url_decode(data);
    std::string data_lower = decoded_data;
    std::transform(data_lower.begin(), data_lower.end(), data_lower.begin(), ::tolower);

    for (int i = 0; i < Config::DPI_SIGNATURES_COUNT; i++) {
        const Config::DPISignature& sig = Config::DPI_SIGNATURES[i];
        
        if (data_lower.find(sig.pattern) != std::string::npos) {
            std::cout << "[DPI] " << sig.category << " from " << ip << std::endl;
            
            std::string json = build_json_alert(
                "DPI_Attack",
                ip,
                d_port,
                "TCP",
                sig.category,
                sig.subcategory,
                static_cast<Config::AlertSeverity>(sig.severity),
                "\"pattern\": \"" + sig.pattern + "\""
            );
            
            Emitter::getInstance()->send_alert(json);
            Emitter::getInstance()->block_ip(ip);
            return;
        }
    }
}

// ============== PROTOCOL HANDLERS ==============

void Detector::handle_tcp(const struct pcap_pkthdr *pkthdr, const u_char *packet,
                          const iphdr *ip, uint16_t src_port, uint16_t dest_port) {
    int ihl = ip->ihl * 4;
    if (pkthdr->len < 14 + ihl + 20) return;

    struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ihl);
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
    std::string ip_str(src_ip);

    time_t now = time(NULL);
    ConnectionInfo &info = tracker[ip_str];

    // DoS detection
    detect_dos(ip_str);

    // SYN packet analysis
    if (tcp->syn && !tcp->ack) {
        info.last_syn_time = now;
        info.last_syn_port = dest_port;
        detect_port_scan(ip_str, dest_port);
    }

    // RST packet - stealth scan indicator
    if (tcp->rst) {
        detect_stealth_scan(ip_str, dest_port);
    }

    // DPI - payload inspection
    int tcp_header_len = tcp->doff * 4;
    int total_headers_size = 14 + ihl + tcp_header_len;

    if (total_headers_size < pkthdr->len) {
        const u_char *payload = packet + total_headers_size;
        int payload_len = pkthdr->len - total_headers_size;
        detect_dpi(payload, payload_len, ip_str, dest_port);
    }
}

void Detector::handle_udp(const struct pcap_pkthdr *pkthdr, const u_char *packet,
                          const iphdr *ip, uint16_t src_port, uint16_t dest_port) {
    (void)src_port;  // Suppress unused parameter warning
    
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
    std::string ip_str(src_ip);

    // DoS detection for UDP
    detect_dos(ip_str);

    int ihl = ip->ihl * 4;
    int udp_header_size = 14 + ihl + 8;

    // Check for DNS amplification (port 53 with large response)
    if (dest_port == 53 && pkthdr->len > 512) {
        std::cout << "[DNS] Large response to " << ip_str << std::endl;
    }

    // DPI for UDP payload
    if (udp_header_size < pkthdr->len) {
        const u_char *payload = packet + udp_header_size;
        int payload_len = pkthdr->len - udp_header_size;
        detect_dpi(payload, payload_len, ip_str, dest_port);
    }
}

void Detector::handle_icmp(const struct pcap_pkthdr *pkthdr, const u_char *packet,
                           const iphdr *ip, const std::string& src_ip) {
    int ihl = ip->ihl * 4;
    if (pkthdr->len < 14 + ihl + 8) return;

    struct icmphdr *icmp = (struct icmphdr *)(packet + 14 + ihl);
    
    // Detect ICMP Flood / Smurf
    detect_dos(src_ip);

    // Type 8 = Echo Request (Ping)
    if (icmp->type == 8) {
        std::cout << "[ICMP] Echo request from " << src_ip << std::endl;
    }
}

// ============== MAIN HANDLER ==============

void Detector::handle_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (pkthdr->len < 34) return;

    struct iphdr *ip = (struct iphdr *)(packet + 14);
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
    std::string ip_str(src_ip);

    // Check whitelist
    if (Config::WHITELIST.count(ip_str)) {
        return;
    }

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + (ip->ihl * 4));
        handle_tcp(pkthdr, packet, ip, ntohs(tcp->source), ntohs(tcp->dest));
    }
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(packet + 14 + (ip->ihl * 4));
        handle_udp(pkthdr, packet, ip, ntohs(udp->source), ntohs(udp->dest));
    }
    else if (ip->protocol == IPPROTO_ICMP) {
        handle_icmp(pkthdr, packet, ip, ip_str);
    }
}

int Detector::get_tracker_size() const {
    return tracker.size();
}

} // namespace NDR
