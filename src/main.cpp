#include <iostream>
#include <pcap.h>
#include <signal.h>
#include <cstdlib>
#include "../include/Detector.hpp"
#include "../include/Emitter.hpp"
#include "../include/Config.hpp"

using namespace NDR;

// Global instances for signal handling
Detector* g_detector = nullptr;
pcap_t* g_handle = nullptr;

void signal_handler(int signum) {
    (void)signum;  // Suppress unused parameter warning
    if (g_handle) pcap_breakloop(g_handle);
    std::cout << "\n[*] Sensor shutting down..." << std::endl;
    exit(0);
}

void packet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)user_data;  // Suppress unused parameter warning
    if (g_detector) {
        g_detector->handle_packet(pkthdr, packet);
    }
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    
    std::cout << "\n";
    std::cout << "╔════════════════════════════════════════╗\n";
    std::cout << "║  NDR System v8 - Modular Sensor      ║\n";
    std::cout << "║  include/ src/ architecture          ║\n";
    std::cout << "╚════════════════════════════════════════╝\n";
    std::cout << "\n";

    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Get detector instance
    g_detector = Detector::getInstance();

    // Open pcap handle
    char errbuf[PCAP_ERRBUF_SIZE];
    g_handle = pcap_open_live("lo", 65535, 1, 1000, errbuf);

    if (!g_handle) {
        std::cerr << "[ERROR] Cannot open interface: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "[✓] Sensor initialized\n";
    std::cout << "[✓] Monitoring: localhost (127.0.0.1)\n";
    std::cout << "[✓] Protocols: TCP, UDP, ICMP\n";
    std::cout << "[✓] Detectors:\n";
    std::cout << "    - Port Scanning (SYN sweep)\n";
    std::cout << "    - Stealth Scanning (SYN->RST pattern)\n";
    std::cout << "    - DoS/DDoS (PPS-based)\n";
    std::cout << "    - DPI (SQL, RCE, XSS, Path Traversal)\n";
    std::cout << "[✓] Python listener: " << Config::SOCK_PATH << "\n";
    std::cout << "\n[*] Listening for packets...\n\n";

    // Start packet capture loop
    if (pcap_loop(g_handle, 0, packet_callback, NULL) < 0) {
        std::cerr << "[ERROR] pcap_loop error: " << pcap_geterr(g_handle) << std::endl;
        pcap_close(g_handle);
        return 1;
    }

    pcap_close(g_handle);
    return 0;
}
