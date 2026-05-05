#!/bin/bash

###############################################################################
# NDR System - WSL2 Testing Suite
# 
# Tests for localhost (127.0.0.1) in WSL2 environment
# Run with: bash tests/wsl_tests.sh
###############################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SENSOR_HOST="127.0.0.1"
LISTENER_SOCKET="/tmp/ndr.sock"
TEST_PORT=8888
TEST_TARGET="172.29.118.47"

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  NDR System - WSL2 Test Suite        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}\n"

# ============== UTILITY FUNCTIONS ==============

check_requirements() {
    echo -e "${YELLOW}[*] Checking requirements...${NC}"
    
    local requirements=("nc" "timeout" "python3" "nmap")
    for cmd in "${requirements[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            echo -e "${RED}[ERROR] Missing: $cmd${NC}"
            return 1
        fi
    done
    echo -e "${GREEN}[✓] All requirements found${NC}\n"
}

check_listener() {
    echo -e "${YELLOW}[*] Checking Python listener...${NC}"
    
    if [ ! -S "$LISTENER_SOCKET" ]; then
        echo -e "${RED}[ERROR] Listener socket not found: $LISTENER_SOCKET${NC}"
        echo -e "${YELLOW}[*] Make sure listener.py is running first!${NC}"
        return 1
    fi
    echo -e "${GREEN}[✓] Listener socket found${NC}\n"
}

check_sensor() {
    echo -e "${YELLOW}[*] Checking C++ sensor...${NC}"
    
    if ! pgrep -f "ndr_sensor" > /dev/null; then
        echo -e "${RED}[ERROR] Sensor not running${NC}"
        echo -e "${YELLOW}[*] Make sure to run: sudo ./ndr_sensor${NC}"
        return 1
    fi
    echo -e "${GREEN}[✓] Sensor is running${NC}\n"
}

# ============== PORT SCAN TEST ==============

test_port_scan() {
    echo -e "${BLUE}=== TEST 1: Port Scanning Detection ===${NC}\n"
    echo -e "${YELLOW}[*] Trigger: nmap -sT (TCP Connect Scan - 5+ ports)${NC}"
    echo -e "${YELLOW}[*] Expected: PortScan alert${NC}"
    echo -e "${YELLOW}[*] Expected: IP should be blocked after 5+ unique ports\n${NC}"
    
    read -p "Ready? Press Enter to start port scan..."
    
    echo -e "${YELLOW}[>] Running: nmap -sT -p 80,443,8080,8443,9000 ${TEST_TARGET}${NC}\n"
    timeout 10 nmap -sT -p 80,443,8080,8443,9000 ${TEST_TARGET} 2>/dev/null || true
    
    echo -e "\n${GREEN}[✓] Port scan test complete${NC}\n"
}

# ============== STEALTH SCAN TEST ==============

test_stealth_scan() {
    echo -e "${BLUE}=== TEST 2: Stealth Scanning Detection ===${NC}\n"
    echo -e "${YELLOW}[*] Trigger: nmap -sS (Stealth SYN Scan - SYN->RST pattern)${NC}"
    echo -e "${YELLOW}[*] Expected: StealthScan alert${NC}"
    echo -e "${YELLOW}[*] Expected: SYN->RST pattern detected x3\n${NC}"
    
    read -p "Ready? Press Enter to start stealth scan..."
    
    echo -e "${YELLOW}[>] Running: nmap -sS -p 80,443,8080,8443,9000 ${TEST_TARGET}${NC}\n"
    timeout 10 nmap -sS -p 80,443,8080,8443,9000 ${TEST_TARGET} 2>/dev/null || true
    
    echo -e "\n${GREEN}[✓] Stealth scan test complete${NC}\n"
}

# ============== DPI TEST ==============

test_dpi_sql_injection() {
    echo -e "${BLUE}=== TEST 3: DPI - SQL Injection Detection ===${NC}\n"
    echo -e "${YELLOW}[*] Trigger: Send SQL injection payload to localhost${NC}"
    echo -e "${YELLOW}[*] Expected: DPI_Attack alert with SQL_Injection category${NC}"
    echo -e "${YELLOW}[*] Expected: IP should be blocked\n${NC}"
    
    read -p "Ready? Press Enter to send SQL injection..."
    
    # Start a simple listener on port 9999
    (nc -l -p 9999 >/dev/null 2>&1 &)
    sleep 1
    
    # Send SQL injection payload
    echo -e "${YELLOW}[>] Sending payload: 'admin' OR '1'='1${NC}\n"
    echo "GET /?user=admin' OR '1'='1 HTTP/1.0\r\n\r\n" | nc localhost 9999 2>/dev/null || true
    
    sleep 1
    pkill -f "nc -l -p 9999" || true
    
    echo -e "\n${GREEN}[✓] SQL injection test complete${NC}\n"
}

# ============== DPI TEST - Path Traversal ==============

test_dpi_path_traversal() {
    echo -e "${BLUE}=== TEST 4: DPI - Path Traversal Detection ===${NC}\n"
    echo -e "${YELLOW}[*] Trigger: Send path traversal payload${NC}"
    echo -e "${YELLOW}[*] Expected: DPI_Attack alert with Path_Traversal category${NC}"
    echo -e "${YELLOW}[*] Expected: IP should be blocked\n${NC}"
    
    read -p "Ready? Press Enter to send path traversal..."
    
    (nc -l -p 9999 >/dev/null 2>&1 &)
    sleep 1
    
    echo -e "${YELLOW}[>] Sending payload: ../../../etc/passwd${NC}\n"
    echo "GET /../../../etc/passwd HTTP/1.0\r\n\r\n" | nc localhost 9999 2>/dev/null || true
    
    sleep 1
    pkill -f "nc -l -p 9999" || true
    
    echo -e "\n${GREEN}[✓] Path traversal test complete${NC}\n"
}

# ============== DOS TEST (Light) ==============

test_dos_light() {
    echo -e "${BLUE}=== TEST 5: DoS Detection (Light) ===${NC}\n"
    echo -e "${YELLOW}[*] Trigger: Flood localhost with 600 packets in 2 seconds${NC}"
    echo -e "${YELLOW}[*] Expected: DoS_Attack alert (PPS > 500)${NC}"
    echo -e "${YELLOW}[*] WARNING: This may cause system lag\n${NC}"
    
    read -p "Ready? Press Enter to start DoS simulation..."
    
    echo -e "${YELLOW}[>] Sending ICMP flood for 2 seconds...${NC}\n"
    timeout 2 ping -f 127.0.0.1 >/dev/null 2>&1 || true
    
    echo -e "\n${GREEN}[✓] DoS test complete${NC}\n"
}

# ============== DATABASE CHECK ==============

test_database_check() {
    echo -e "${BLUE}=== TEST 6: Database Check ===${NC}\n"
    
    local db_path="/tmp/ndr_alerts.db"
    
    if [ ! -f "$db_path" ]; then
        echo -e "${RED}[ERROR] Database not found: $db_path${NC}\n"
        return 1
    fi
    
    echo -e "${YELLOW}[*] Querying alerts from database...${NC}\n"
    
    # Count alerts
    local alert_count=$(sqlite3 "$db_path" "SELECT COUNT(*) FROM alerts;" 2>/dev/null || echo "0")
    local ban_count=$(sqlite3 "$db_path" "SELECT COUNT(*) FROM ip_bans WHERE status='active';" 2>/dev/null || echo "0")
    
    echo -e "${GREEN}[✓] Total alerts logged: $alert_count${NC}"
    echo -e "${GREEN}[✓] Active bans: $ban_count${NC}\n"
    
    # Show last 5 alerts
    echo -e "${YELLOW}[*] Last 5 alerts:${NC}\n"
    sqlite3 "$db_path" "SELECT timestamp, alert_type, severity_name, src_ip FROM alerts ORDER BY id DESC LIMIT 5;" 2>/dev/null || true
    
    echo -e "\n"
}

# ============== MAIN TEST MENU ==============

main() {
    check_requirements || exit 1
    check_listener || exit 1
    check_sensor || exit 1
    
    echo -e "${YELLOW}Select tests to run:${NC}\n"
    echo "1. Port Scan Detection"
    echo "2. Stealth Scan Detection"
    echo "3. DPI - SQL Injection"
    echo "4. DPI - Path Traversal"
    echo "5. DoS Detection (Light)"
    echo "6. Database Check"
    echo "7. Run All Tests"
    echo "0. Exit\n"
    
    read -p "Enter your choice [0-7]: " choice
    
    case $choice in
        1) test_port_scan ;;
        2) test_stealth_scan ;;
        3) test_dpi_sql_injection ;;
        4) test_dpi_path_traversal ;;
        5) test_dos_light ;;
        6) test_database_check ;;
        7)
            test_port_scan
            test_stealth_scan
            test_dpi_sql_injection
            test_dpi_path_traversal
            test_dos_light
            test_database_check
            ;;
        0) echo -e "${GREEN}Goodbye!${NC}"; exit 0 ;;
        *) echo -e "${RED}Invalid choice${NC}"; main ;;
    esac
    
    echo -e "${YELLOW}Run another test? (y/n): ${NC}"
    read -p "" run_again
    if [ "$run_again" = "y" ] || [ "$run_again" = "Y" ]; then
        main
    fi
}

main
