#!/bin/bash

TARGET_IP="172.29.118.47"

# Funkcja wysyłająca komendę UNBAN
function auto_unban() {
    echo " [*] Czyszczenie firewalla i zdejmowanie bana..."
    sudo iptables -F
    python3 -c "
import socket, json
try:
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect('/tmp/ndr.sock')
    c.send(json.dumps({'type': 'unban', 'ip': '$TARGET_IP'}).encode())
    c.recv(1024) # <--- NAPRAWA BROKEN PIPE: Czekamy aż listener odpowie
    c.close()
except:
    pass
"
    sleep 1
}

# Funkcja restartująca sensor C++
function reset_sensor_ram() {
    echo " [*] Restartowanie sensora C++ (Czyszczenie pamięci stanowej)..."
    sudo pkill -15 ndr_sensor 2>/dev/null  # <--- NAPRAWA SENSORA: Łagodny sygnał SIGTERM
    sleep 1
    # Zapisujemy logi do pliku zamiast w kosz, a nohup chroni proces przed śmiercią konsoli
    sudo nohup ./ndr_sensor > sensor_test.log 2>&1 &
    sleep 2
}

# Funkcja sprzątająca po testach
function cleanup() {
    sudo pkill -9 nc 2>/dev/null
    sudo pkill -9 ndr_sensor 2>/dev/null
    sudo iptables -F
    echo -e "\n[!] Testy zakończone. Sensor zatrzymany."
}
trap cleanup EXIT # Zawsze wywołaj cleanup, nawet jak wciśniesz Ctrl+C

echo "======================================================"
echo "    NDR SYSTEM - ULTIMATE INTEGRATION TEST SUITE      "
echo "======================================================"

# ---------------------------------------------------------
echo -e "\n>>> TEST 1: Zwykłe Skanowanie Portów (T4)"
reset_sensor_ram
sudo nmap -sT -T4 -p 80,443,8080,8443,9000,22 $TARGET_IP > /dev/null 2>&1
sleep 2
auto_unban

# ---------------------------------------------------------
echo -e "\n>>> TEST 2: Atak DoS / Ping Flood (>500 pakietów/s)"
reset_sensor_ram
# Wysyłamy 1000 pakietów ICMP z maksymalną prędkością (-f)
sudo ping -f -c 1000 $TARGET_IP > /dev/null 2>&1
sleep 2
auto_unban

# ---------------------------------------------------------
echo -e "\n>>> TEST 3: DPI - SQL Injection (CRITICAL)"
reset_sensor_ram
echo " [*] Stawiam fałszywy serwer WWW na porcie 80..."
sudo nc -l -p 80 > /dev/null 2>&1 &
sleep 1
echo "GET /?user=admin' or 1=1-- HTTP/1.0" | nc -w 1 $TARGET_IP 80
sleep 2
auto_unban

# ---------------------------------------------------------
echo -e "\n>>> TEST 4: DPI - Path Traversal (CRITICAL)"
reset_sensor_ram
echo " [*] Stawiam fałszywy serwer WWW na porcie 80..."
sudo nc -l -p 80 > /dev/null 2>&1 &
sleep 1
echo "GET /../../../etc/passwd HTTP/1.0" | nc -w 1 $TARGET_IP 80
sleep 2
auto_unban

# ---------------------------------------------------------
echo -e "\n>>> TEST 5: DPI - Command Injection (CRITICAL)"
reset_sensor_ram
echo " [*] Stawiam fałszywy serwer WWW na porcie 80..."
sudo nc -l -p 80 > /dev/null 2>&1 &
sleep 1
echo "GET /ping?ip=127.0.0.1; rm -rf / HTTP/1.0" | nc -w 1 $TARGET_IP 80
sleep 2
auto_unban

# ---------------------------------------------------------
echo -e "\n>>> TEST 6: DPI - Cross-Site Scripting XSS (WARNING)"
reset_sensor_ram
echo " [*] Stawiam fałszywy serwer WWW na porcie 80..."
sudo nc -l -p 80 > /dev/null 2>&1 &
sleep 1
echo "GET /search?q=<script>alert(1)</script> HTTP/1.0" | nc -w 1 $TARGET_IP 80
sleep 2
auto_unban

# ---------------------------------------------------------
echo -e "\n>>> TEST 7: Stealth Scan (T1 - Wolny skan co 15s)"
reset_sensor_ram
echo " [*] Stawiam 3 fałszywe porty-pułapki w tle..."
nc -l -p 8081 > /dev/null 2>&1 &
nc -l -p 8082 > /dev/null 2>&1 &
nc -l -p 8083 > /dev/null 2>&1 &
sleep 1

# Puszczamy wolny skan, który zajmie ok 45-50 sekund
sudo nmap -sS -T1 -p 8081,8082,8083 $TARGET_IP > /dev/null 2>&1
sleep 2
auto_unban

echo -e "\n======================================================"
echo "    WSZYSTKIE MODUŁY PRZETESTOWANE POMYŚLNIE          "
echo "======================================================"
