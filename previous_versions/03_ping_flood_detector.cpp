#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <ctime>

int icmp_count = 0;
time_t start_time = time(0);

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct iphdr *ip = (struct iphdr *)(packet + 14);

    if (ip->protocol == IPPROTO_ICMP) {
        icmp_count++;
        
        time_t current_time = time(0);
        if (current_time - start_time >= 1) {
            if (icmp_count > 10) { 
                std::cout << "!!! [ALERT] Wykryto Ping Flood! (" << icmp_count << " pak./s)" << std::endl;
            }
            icmp_count = 0;
            start_time = current_time;
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("eth0", 65535, 1, 100, errbuf);
    if (!handle) return 1;

    std::cout << "Monitorowanie pod kątem Ping Flood..." << std::endl;
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
