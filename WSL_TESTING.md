# Przewodnik Testowania WSL2 dla Systemu NDR

## Zrozumienie Sieci WSL2

### Architektura Sieciowa w WSL2

```
┌─────────────────────────────────────┐
│         Windows (System Operacyjny)  │
│                                     │
│  ┌──────────────────────────────┐   │
│  │    Maszyna Wirtualna WSL2    │   │
│  │  (172.29.118.X - Wewnętrzna) │   │
│  │                              │   │
│  │  [Sensor NDR]   [Listener.py]│   │
│  └──────────────────────────────┘   │
│                                     │
└─────────────────────────────────────┘
         ↑
    Brama NAT (172.29.112.1)
         ↑
    Windows 10/11 Hyper-V
         ↑
    Sieć Fizyczna (192.168.1.X)
```

### Kluczowe Punkty:

1. **WSL2 używa NAT (Network Address Translation)**
   - Twój adres WSL (np. `172.29.118.47`) jest wewnętrzny dla mostu Hyper-V
   - Urządzenia zewnętrzne (laptopy, routery) nie mogą bezpośrednio dotrzeć do IP WSL2
   - Tylko ruch localhost (127.0.0.1) jest dostępny z Windows

2. **Dlaczego testowanie localhost działa:**
   - interfejs loopback (lo) przenosi cały ruch 127.0.0.1
   - Sensor przechwytuje je na lo, które nie są trasowane przez NAT
   - Idealne dla rozwoju i testowania izolowanego

3. **Dlaczego testowanie z urządzeń zewnętrznych NIE zadziała:**
   - Atakujący w sieci wysyła pakiet do IP Windows (192.168.1.X)
   - Jądro Windows nie przekierowuje do WSL2
   - Sensor nigdy go nie widzi (chyba że skonfigurujesz port forwarding)

## Scenariusze Testowania

### Scenariusz 1: Testowanie Localhost (Działa w WSL2)

**Konfiguracja:**
```bash
# Terminal 1 (WSL2)
python3 listener.py

# Terminal 2 (WSL2)
sudo ./ndr_sensor

# Terminal 3 (WSL2 lub Windows)
nmap -sS -p 80,443,8080 127.0.0.1
```

**Rezultat:** Sensor wykrywa skan OK

**Dlaczego działa:**
- Cały ruch pozostaje na interfejsie loopback
- Localhost trasuje się wewnętrznie
- Brak NAT w żaden sposób

---

### Scenariusz 2: Testowanie Wewnętrznego IP WSL2 (Nie działa z Windows)

**Próba:**
```bash
# Windows PowerShell
nmap -sS -p 80,443 172.29.118.47
```

**Rezultat:** Timeout

**Dlaczego nie działa:**
- Stack sieciowy Windows nie wie jak trasować do 172.29.118.X
- To wewnętrzny most Hyper-V tylko
- Narzędzia zewnętrzne na Windows nie mogą do niego dotrzeć

---

### Scenariusz 3: Testowanie Urządzeń Sieciowych (Nie działa w WSL2)

**Próba:**
```bash
# Atakujący na innym laptopie (192.168.1.Y)
nmap -sS 192.168.1.X  # Twój IP Windows

# Potem na WSL2
sudo ./ndr_sensor
```

**Rezultat:** Sensor nie wykrywa

**Dlaczego:**
- Firewall Windows filtruje ruch przychodzący
- Sensor nasłuchuje na lo (localhost tylko)
- Pakiety przychodzą do Windows, nie trafiają do WSL2
- Wymaga port mirroring lub WSL Mirrored Networking mode

---

## Zaawansowane: Włącz Port Forwarding (Opcjonalne)

### Opcja A: Windows Port Forwarding (Tymczasowe)

```powershell
# PowerShell (jako Administrator)
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=8080 connectaddress=172.29.118.47
```

Potem z innego urządzenia:
```bash
nmap 192.168.1.X:8080
```

**Plusy:** Działa od razu
**Minusy:** Ręczna konfiguracja per port, wymaga admina

### Opcja B: WSL Mirrored Networking (Windows 11 Build 22000+)

Edytuj `%UserProfile%\.wslconfig`:
```ini
[wsl2]
networkingMode=mirrored
```

Potem restart WSL:
```powershell
wsl --shutdown
```

**Plusy:** WSL otrzymuje ten sam IP co Windows, bezpośredni dostęp
**Minusy:** Wymaga najnowszego Windows 11, mogą być problemy kompatybilności

### Opcja C: Testowanie Sprzętu (Najlepsza Opcja)

Wdróż na Mini PC/Raspberry Pi z:
- Fizycznym NIC (eth0)
- Switchem ze SPAN (port mirroring)
- Bez NAT

---

## Matryca Testów

| Scenariusz | Z | Do | Działa | Uwagi |
|----------|-----|-------|-------|-------|
| **Localhost** | WSL2 localhost | 127.0.0.1 | Tak | Domyślne środowisko testowe |
| **Wewnętrzne WSL** | Windows | 172.29.118.47 | Nie | Bariera NAT |
| **Wewnętrzne WSL** | WSL do WSL | 172.29.118.47 | Tak | Ta sama VM |
| **Zewnętrzne** | Inne urządzenie | 192.168.1.X | Nie | Bez konfiguracji |
| **Z Port Forward** | Inne urządzenie | 192.168.1.X:PORT | Tak | Ręczna konfiguracja |
| **Mirrored Mode** | Inne urządzenie | Windows IP | Tak | Tylko Win 11+ |
| **Sprzęt** | Sieć fizyczna | Device IP | Tak | Gotowe do produkcji |

---

## Zalecana Ścieżka Testowania

### Faza 1: Rozwój (Jesteś tutaj)
```
Używaj localhost (127.0.0.1)
Testuj wszystkie typy detekcji
Weryfikuj format JSON
Sprawdzaj funkcjonalność dashboardu
```

### Faza 2: Walidacja
```
Ustaw port forwarding jeśli potrzeba
Testuj z innej instancji WSL2
Waliduj detekcję multi-IP
```

### Faza 3: Produkcja
```
Wdróż na Mini PC (Debian/Ubuntu bare metal)
Skonfiguruj switch zarządzany ze SPAN
Uruchom testy obciążenia
Monitoruj system pod ruchem 1Gbps+
```

---

## Uruchamianie Testów w WSL2

```bash
# Ustaw test script jako wykonywalny
chmod +x tests/wsl_tests.sh

# Uruchom interaktywny test suite
bash tests/wsl_tests.sh
```

**Opcje testów:**
1. Detekcja Skanowania Portów
2. Detekcja Skanowania Ukrytego
3. DPI - SQL Injection
4. DPI - Path Traversal
5. Detekcja DoS
6. Sprawdzenie Bazy Danych
7. Uruchom Wszystkie Testy

---

## Przykład Wyniku Testów

```
[*] Sprawdzanie wymagań...
[Tak] Wszystkie wymagania spełnione

[*] Sprawdzanie Python listenera...
[Tak] Socket listenera znaleziony

[*] Sprawdzanie C++ sensora...
[Tak] Sensor jest uruchomiony

=== TEST 1: Detekcja Skanowania Portów ===

[*] Wyzwalacz: nmap -sT (5+ portów)
[>] Uruchamianie: nmap -sT -p 80,443,8080,8443,9000 127.0.0.1

Starting Nmap 7.80 ( https://nmap.org )...

[SCAN] Port sweep from 127.0.0.1 (6 ports)  <- Sensor wykrył!

[Tak] Test skanowania portów zakończony
```

---

## Debugowanie Problemów Połączenia

### Sprawdź czy listener jest uruchomiony:
```bash
ls -la /tmp/ndr.sock
```

### Sprawdź czy sensor jest uruchomiony:
```bash
ps aux | grep ndr_sensor
```

### Monitoruj alerty w czasie rzeczywistym:
```bash
# Terminal z uruchomionym listenerem
# Powinien pokazować alerty w miarę ich przybycia
```

### Sprawdzenie bazy danych:
```bash
sqlite3 /tmp/ndr_alerts.db "SELECT COUNT(*) FROM alerts;"
```

### Weryfikacja reguł firewall:
```bash
sudo iptables -L INPUT -n -v
```

---

## Uwagi Wydajnościowe

**Na WSL2 localhost:**
- Może obsłużyć ~10,000 pakietów/sekundo
- Typowe skanowanie portów: 50-200 pakietów/sekundo
- Skanowanie ukryte: ~10 pakietów/sekundo
- Test DoS: używaj ostrożnie (może zamrozić WSL)

**Zalecany bezpieczny test DoS:**
```bash
# Limit do 1 sekundy zamiast 2
timeout 1 ping -f 127.0.0.1
```

---

## Ograniczenia WSL i Rozwiązania

| Ograniczenie | Obejście | Status |
|-----------|-----------|--------|
| Brak dostępu zewnętrznego | Testowanie localhost | Gotowe |
| Mostek NAT | Port forwarding lub mirrored networking | Częściowo |
| Reguły iptables mogą się nie utrzymać | Użyj firewall specyficzny dla WSL | Znane |
| Ograniczona wydajność | Wdrożenie na sprzęcie | Zaplanowane |

---

## Co Testować Dla Oceny

- [x] Sensor kompiluje się bez błędów
- [x] Listener startuje i akceptuje połączenia
- [x] Wszystkie typy detekcji uruchamiają się prawidłowo
- [x] Format JSON jest prawidłowy i kompletny
- [x] Dashboard wyświetla dane prawidłowo
- [x] Baza loguje wszystkie zdarzenia
- [x] Eskalacja banu działa (5→10→60 min)
- [x] Cleanup usuwa wygasłe bany
- [ ] Wydajność na ruchu 1Gbps+ (wymaga sprzętu)

---

**Następny Krok:** Przystąp do testowania sprzętu gdy będzie dostępny (Mini PC + Managed Switch)
