#include <iostream>
#include <pcap.h>
#include <signal.h>
#include <cstdlib>
#include "../include/Detector.hpp"
#include "../include/Emitter.hpp"
#include "../include/Config.hpp"

using namespace NDR;

Detector* g_detector = nullptr;
pcap_t* g_handle = nullptr;
int g_link_offset = 14; // Domyślny offset dla Ethernetu

void signal_handler(int signum) {
    (void)signum; 
    if (g_handle) pcap_breakloop(g_handle);
    std::cout << "\n[*] Sensor shutting down..." << std::endl;
    exit(0);
}

void packet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)user_data;
    if (g_detector) {
        // Przekazanie dynamicznego offsetu do detektora
        g_detector->handle_packet(pkthdr, packet, g_link_offset);
    }
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    
    std::cout << "\n╔════════════════════════════════════════╗\n";
    std::cout << "║  NDR System v8 - Modular Sensor      ║\n";
    std::cout << "║  include/ src/ architecture          ║\n";
    std::cout << "╚════════════════════════════════════════╝\n\n";

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    g_detector = Detector::getInstance();

    char errbuf[PCAP_ERRBUF_SIZE];
    
    // AUTODETEKCJA SYSTEMU DLA INTERFEJSU
#ifdef __APPLE__
    const char* dev = "lo0"; // macOS loopback
#else
    const char* dev = "lo";  // Linux/WSL loopback
#endif

    g_handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    if (!g_handle) {
        std::cerr << "[ERROR] Cannot open interface " << dev << ": " << errbuf << std::endl;
        return 1;
    }

    // DYNAMICZNY OFFSET
    int datalink = pcap_datalink(g_handle);
    if (datalink == DLT_NULL) {
        g_link_offset = 4;   // Nagłówek Loopback/Null (macOS)
    } else if (datalink == DLT_EN10MB) {
        g_link_offset = 14;  // Standardowy Ethernet (Linux)
    }

    // BPF FILTER (ODMRAŻANIE MACA)
    // Ignorujemy ruch z Dashboardu (Flask) oraz ruch SSH, aby uniknąć pętli
    struct bpf_program fp;
    std::string filter_exp = "not port 5000 and not port 5001 and not port 22";
    if (pcap_compile(g_handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "[ERROR] pcap_compile failed: " << pcap_geterr(g_handle) << std::endl;
        return 1;
    }
    if (pcap_setfilter(g_handle, &fp) == -1) {
        std::cerr << "[ERROR] pcap_setfilter failed: " << pcap_geterr(g_handle) << std::endl;
        return 1;
    }
    pcap_freecode(&fp);

    std::cout << "[✓] Sensor initialized\n";
    std::cout << "[✓] Monitoring: " << dev << " (Offset: " << g_link_offset << " bytes)\n";
    std::cout << "[✓] BPF Filter applied: " << filter_exp << "\n";
    std::cout << "[✓] Python listener: " << Config::SOCK_PATH << "\n";
    std::cout << "\n[*] Listening for packets...\n\n";

    if (pcap_loop(g_handle, 0, packet_callback, NULL) < 0) {
        std::cerr << "[ERROR] pcap_loop error: " << pcap_geterr(g_handle) << std::endl;
        pcap_close(g_handle);
        return 1;
    }

    pcap_close(g_handle);
    return 0;
}