#ifndef NDR_EMITTER_HPP
#define NDR_EMITTER_HPP

#include <string>
#include <set>
#include "Config.hpp"

namespace NDR {

class Emitter {
private:
    std::set<std::string> blocked_ips;
    static Emitter* instance;

public:
    static Emitter* getInstance() {
        if (!instance) instance = new Emitter();
        return instance;
    }

    /**
     * Send alert via Unix socket to Python listener
     * @param json_message Alert in JSON format
     */
    void send_alert(const std::string& json_message);

    /**
     * Block IP using iptables
     * @param ip IP address to block
     * @return true if successful or already blocked
     */
    bool block_ip(const std::string& ip);

    /**
     * Check if IP is blocked
     * @param ip IP address
     * @return true if blocked
     */
    bool is_blocked(const std::string& ip) const;

    /**
     * Get count of blocked IPs
     * @return Number of currently blocked IPs
     */
    int get_blocked_count() const;
};

} // namespace NDR

#endif // NDR_EMITTER_HPP
