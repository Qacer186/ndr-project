#include "../include/Emitter.hpp"
#include <iostream>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstring>

namespace NDR {

Emitter* Emitter::instance = nullptr;

void Emitter::send_alert(const std::string& json_message) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct sockaddr_un serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sun_family = AF_UNIX;
    strncpy(serv_addr.sun_path, Config::SOCK_PATH.c_str(), sizeof(serv_addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
        ssize_t bytes_sent = send(sock, json_message.c_str(), json_message.length(), 0);
        (void)bytes_sent;  // Suppress unused variable warning
    }
    close(sock);
}

bool Emitter::block_ip(const std::string& ip) {
    // Check whitelist
    if (Config::WHITELIST.count(ip)) {
        return false;
    }

    // Already blocked
    if (blocked_ips.count(ip)) {
        return false;
    }

    // Apply iptables rule
    std::string command = "iptables -A INPUT -s " + ip + " -j DROP 2>/dev/null";
    int result = system(command.c_str());
    
    if (result == 0) {
        blocked_ips.insert(ip);
        return true;
    }
    return false;
}

bool Emitter::is_blocked(const std::string& ip) const {
    return blocked_ips.count(ip) > 0;
}

int Emitter::get_blocked_count() const {
    return blocked_ips.size();
}

} // namespace NDR
