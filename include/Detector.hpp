#ifndef NDR_DETECTOR_HPP
#define NDR_DETECTOR_HPP

#include <string>
#include <map>
#include <set>
#include <vector>
#include <ctime>
#include <pcap.h>
#include <netinet/ip.h>  // Added for struct iphdr definition
#include "Config.hpp"

namespace NDR {

// ============== CONNECTION TRACKING STATE ==============
struct ConnectionInfo {
    // TCP Port Scan Detection
    time_t last_syn_time;
    uint16_t last_syn_port;
    std::set<uint16_t> scanned_ports;
    time_t first_syn_time;
    
    // Stealth Scan Detection (SYN->RST pattern)
    int stealth_hit_count;
    bool is_stealth_flagged;
    
    // DoS/DDoS Detection (PPS - packets per second)
    int packet_count;
    time_t last_reset;
    
    // General tracking
    int attack_count;
    time_t last_attack_time;

    // Constructor
    ConnectionInfo() : 
        last_syn_time(0), last_syn_port(0), first_syn_time(0),
        stealth_hit_count(0), is_stealth_flagged(false),
        packet_count(0), last_reset(time(NULL)),
        attack_count(0), last_attack_time(0) {}
};

// ============== DETECTOR CLASS ==============
class Detector {
private:
    std::map<std::string, ConnectionInfo> tracker;
    static Detector* instance;

    // ===== UTILITY METHODS =====
    std::string get_timestamp();
    std::string url_decode(const std::string& encoded);
    std::string severity_to_string(Config::AlertSeverity sev);
    
    std::string build_json_alert(
        const std::string& alert_type,
        const std::string& src_ip,
        uint16_t dest_port,
        const std::string& protocol,
        const std::string& category,
        const std::string& signature,
        Config::AlertSeverity severity,
        const std::string& additional_data = ""
    );

    // ===== DETECTION METHODS =====
    void detect_dos(const std::string& ip);
    void detect_stealth_scan(const std::string& ip, uint16_t d_port);
    void detect_port_scan(const std::string& ip, uint16_t d_port);
    void detect_dpi(const u_char *payload, int payload_len, const std::string& ip, uint16_t d_port);

public:
    static Detector* getInstance() {
        if (!instance) instance = new Detector();
        return instance;
    }

    /**
     * Main packet handler - routes to protocol-specific handlers
     */
    void handle_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet);

    /**
     * Protocol-specific handlers
     */
    void handle_tcp(const struct pcap_pkthdr *pkthdr, const u_char *packet, 
                    const iphdr *ip, uint16_t src_port, uint16_t dest_port);
    void handle_udp(const struct pcap_pkthdr *pkthdr, const u_char *packet, 
                    const iphdr *ip, uint16_t src_port, uint16_t dest_port);
    void handle_icmp(const struct pcap_pkthdr *pkthdr, const u_char *packet, 
                     const iphdr *ip, const std::string& src_ip);

    /**
     * Get tracker size (for debugging)
     */
    int get_tracker_size() const;
};

} // namespace NDR

#endif // NDR_DETECTOR_HPP
