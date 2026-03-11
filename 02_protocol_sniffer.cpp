#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct iphdr *ip = (struct iphdr *)(packet + 14);
    int ip_header_len = ip->ihl * 4;

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_header_len);
        std::cout << "[TCP] " << src_ip << ":" << ntohs(tcp->source) << " -> " << dst_ip << ":" << ntohs(tcp->dest) << std::endl;
    } 
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(packet + 14 + ip_header_len);
        std::cout << "[UDP] " << src_ip << ":" << ntohs(udp->source) << " -> " << dst_ip << ":" << ntohs(udp->dest) << std::endl;
    }
    else if (ip->protocol == IPPROTO_ICMP) {
        std::cout << "[ICMP] " << src_ip << " -> " << dst_ip << std::endl;
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("eth0", 65535, 1, 1000, errbuf);

    if (!handle) return 1;

    std::cout << "Nasłuchiwanie... (Ctrl+C aby przerwać)" << std::endl;
    pcap_loop(handle, 0, packet_handler, NULL); // 0 oznacza pętlę nieskończoną

    pcap_close(handle);
    return 0;
}