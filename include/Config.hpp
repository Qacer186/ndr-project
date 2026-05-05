#ifndef NDR_CONFIG_HPP
#define NDR_CONFIG_HPP

#include <string>
#include <set>
#include <map>

namespace NDR {
namespace Config {

// ============== SOCKET CONFIGURATION ==============
const std::string SOCK_PATH = "/tmp/ndr.sock";
const std::string DB_PATH = "/tmp/ndr_alerts.db";

// ============== WHITELIST ==============
const std::set<std::string> WHITELIST = {
    "127.0.0.1",           // localhost
    "::1",                 // localhost IPv6
    "172.29.112.1",        // WSL2 gateway (typical)
    "192.168.1.1",         // typical gateway
    "192.168.0.1",         // typical gateway
    "10.0.0.1"             // typical gateway (private)
};

// ============== DETECTION THRESHOLDS ==============
const int PORT_SCAN_THRESHOLD = 5;              // porty w ciągu 5s
const int STEALTH_PATTERN_THRESHOLD = 3;        // SYN->RST powtórzenia
const int STEALTH_TIME_WINDOW = 1;              // okno czasowe (sekundy)
const int DOS_PACKET_THRESHOLD = 500;           // pakiety/s
const int DOS_TIME_WINDOW = 1;                  // sekundy

// ============== ALERT SEVERITY ==============
enum AlertSeverity {
    INFO = 1,
    WARNING = 2,
    CRITICAL = 3
};

// ============== DPI SIGNATURES ==============
struct DPISignature {
    std::string pattern;
    std::string category;      // SQL_Injection, Path_Traversal, etc.
    std::string subcategory;   // union, drop, etc.
    int severity;
};

// DPI rules database
const DPISignature DPI_SIGNATURES[] = {
    // SQL Injection (Severity: CRITICAL)
    {"union select", "SQL_Injection", "union", 3},
    {"drop table", "SQL_Injection", "drop_table", 3},
    {"select * from", "SQL_Injection", "select", 3},
    {"' or '1'='1", "SQL_Injection", "auth_bypass", 3},
    {"' or 1=1", "SQL_Injection", "auth_bypass", 3},
    {"exec(", "SQL_Injection", "stored_proc", 3},
    
    // Path Traversal & File Access (CRITICAL)
    {"/etc/passwd", "Path_Traversal", "unix_shadow", 3},
    {"/etc/shadow", "Path_Traversal", "unix_shadow", 3},
    {"../../../", "Path_Traversal", "directory_escape", 3},
    {"..\\..\\..\\", "Path_Traversal", "windows_escape", 3},
    {"C:\\windows", "Path_Traversal", "windows_system", 3},
    
    // Command Injection (CRITICAL)
    {"/bin/sh", "Command_Injection", "shell", 3},
    {"/bin/bash", "Command_Injection", "bash", 3},
    {"cmd.exe", "Command_Injection", "windows_cmd", 3},
    {"powershell", "Command_Injection", "powershell", 3},
    {"; rm -rf", "Command_Injection", "destructive", 3},
    
    // XSS (WARNING)
    {"<script>", "XSS", "script_tag", 2},
    {"javascript:", "XSS", "javascript_uri", 2},
    {"onerror=", "XSS", "event_handler", 2},
    
    // LDAP Injection (WARNING)
    {"*)(uid", "LDAP_Injection", "filter", 2},
    {"admin*", "LDAP_Injection", "wildcard", 2}
};

const int DPI_SIGNATURES_COUNT = sizeof(DPI_SIGNATURES) / sizeof(DPI_SIGNATURES[0]);

} // namespace Config
} // namespace NDR

#endif // NDR_CONFIG_HPP
