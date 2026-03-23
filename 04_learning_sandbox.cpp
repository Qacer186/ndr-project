#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <map>
#include <set>
#include <string>
#include <ctime>

// Connection state tracking
struct ConnectionInfo {
    time_t last_syn_time;
    uint16_t last_syn_port;
    std::set<uint16_t> scanned_ports;
    time_t first_syn_time;
    int stealth_hit_count;
};

std::map<std::string, ConnectionInfo> tracker;

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
                info.scanned_ports.clear(); 
            }
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("eth0", 65535, 1, 1000, errbuf);

    if (!handle) return 1;

    std::cout << "Sensor NDR: Monitorowanie wzorców skanowania..." << std::endl;
    pcap_loop(handle, 0, packet_handler, NULL);
    
    pcap_close(handle);
    return 0;
}