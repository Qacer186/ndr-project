# Szybki Start - System NDR

**Czas do pierwszego alertu:** ~2 minuty

## 5-Krokowa Instalacja

### Krok 1: Kompilacja Sensora (30 sekund)
```bash
cd NDR_System
make clean && make
```

Expected output:
```
Compiling src/main.cpp...
Compiling src/Detector.cpp...
Compiling src/Emitter.cpp...
✓ Sensor compiled successfully: ndr_sensor
```

### Krok 2: Terminal 1 - Uruchomienie Listenera
```bash
python3 listener.py
```

Expected output:
```
================================
  NDR System v6 - Listener
  Rich JSON + SQLite + Bans
================================

[✓] Baza danych zainicjalizowana: /tmp/ndr_alerts.db
[*] Python Listener: Oczekiwanie na alerty na /tmp/ndr.sock...
```

### Krok 3: Terminal 2 - Uruchomienie Sensora
```bash
sudo ./ndr_sensor
```

Expected output:
```
╔════════════════════════════════════════╗
║  NDR System v8 - Modular Sensor      ║
║  include/ src/ architecture          ║
╚════════════════════════════════════════╝

[✓] Sensor initialized
[✓] Monitoring: localhost (127.0.0.1)
[✓] Protocols: TCP, UDP, ICMP
[✓] Detectors:
    - Port Scanning (SYN sweep)
    - Stealth Scanning (SYN->RST pattern)
    - DoS/DDoS (PPS-based)
    - DPI (SQL, RCE, XSS, Path Traversal)

[*] Listening for packets...
```

### Krok 4: Terminal 3 - Wyzwolenie Ataku
```bash
# Opcja A: Skanowanie Portów (Stealth)
nmap -sS -p 80,443,8080,8443,9000 127.0.0.1

# Opcja B: Skanowanie Portów (Connect)
nmap -sT -p 80,443,8080,8443,9000 127.0.0.1

# Opcja C: SQL Injection przez netcat
(nc -l -p 9999 >/dev/null 2>&1 &)
sleep 1
echo "GET /?id=1' OR '1'='1 HTTP/1.0" | nc localhost 9999
```

### Krok 5: Terminal 4 - Widok Dashboardu
```bash
cd dashboard
python3 app.py
```

Następnie otwórz: `http://127.0.0.1:5001`

---

## Oczekiwane Rezultaty

### W Terminalu Sensora (Terminal 2)
```
[SCAN] Port sweep from 127.0.0.1 (6 ports)
```
lub
```
[STEALTH] nmap -sS from 127.0.0.1
```
lub
```
[DPI] SQL_Injection from 127.0.0.1
```

### W Terminalu Listenera (Terminal 1)
```
[ALERT ODEBRANY]
  Typ:      PortScan
  Poziom:   WARNING
  IP:       127.0.0.1
  Port:     443
  Protocol: TCP
  Sygnatura: port_sweep
  Czas:     2026-05-04T14:23:45Z
```

### W Dashboardzie (http://127.0.0.1:5001)
- Total Alerts: incrementing counter
- Active Bans: shows 1 after escalation
- Charts: severity & type distribution
- Recent Alerts table: live updates every 5s

---

## Rozwiązywanie Problemów

### "Port already in use" (Dashboard)
```bash
# Change port in dashboard/app.py
app.run(port=5001)  # Use 5001 instead
```

### "Cannot open interface: No such device"
```bash
# Ensure running in WSL2 Linux, not Windows PowerShell
wsl bash
```

### "Permission denied" (Sensor)
```bash
# Sensor needs root for iptables
sudo ./ndr_sensor
```

### "Socket not found: /tmp/ndr.sock"
```bash
# Uruchom listener.py NAJPIERW, potem sensor
# Listener tworzy socket
```

---

## Co Się Dzieje W Tle

1. **Sensor (C++)** przechwytuje pakiety via libpcap
2. **Detector** analizuje nagłówki TCP/UDP/ICMP + payload (DPI)
3. **Emitter** wysyła alert jako JSON via Unix socket → `/tmp/ndr.sock`
4. **Listener (Python)** odbiera JSON, parsuje go
5. **SQLite** loguje alert do tabeli `alerts`
6. **Logika eskalacji** sprawdza czy ban jest potrzebny
7. **Blokowanie IP** nakłada regułę iptables jeśli zostanie wyzwolone
8. **Dashboard** odpytuje bazę co 5s, wyświetla wykresy

---

## Następne Kroki

1. **Uruchom testy** (3-5 minut)
   ```bash
   bash tests/wsl_tests.sh
   ```

2. **Badaj funkcje dashboardu**
   - Kliknij na wiersze alertów aby zobaczyć szczegóły
   - Wyświetl aktywne bany
   - Sprawdź statystyki

3. **Modyfikuj progi** (include/Config.hpp)
   - Dostosuj `PORT_SCAN_THRESHOLD` (obecnie 5 portów)
   - Zmień `DOS_PACKET_THRESHOLD` (obecnie 500 PPS)

4. **Dodaj sygnatury DPI** (include/Config.hpp)
   - Dodaj wzorce do tablicy `DPI_SIGNATURES[]`

---

## Podsumowanie Architektury

```
C++ Sensor (ndr_sensor)
    ↓ (detects)
Rich JSON alerts
    ↓ (Unix socket)
Python Listener (listener.py)
    ↓ (stores)
SQLite Database (/tmp/ndr_alerts.db)
    ↓ (queries)
Flask Dashboard (http://127.0.0.1:5000)
    ↓ (displays)
Web UI (Bootstrap + Chart.js)
```

---

## Lista Weryfikacyjna

After setup, verify:
- [ ] Sensor running with sudo
- [ ] Listener socket exists: `ls /tmp/ndr.sock`
- [ ] Database exists: `ls /tmp/ndr_alerts.db`
- [ ] Dashboard loads at http://127.0.0.1:5000
- [ ] Nmap/netcat triggers detection
- [ ] Alert appears in dashboard within 5 seconds

---

**You're ready!** 🚀 Enjoy inbound alerts.
