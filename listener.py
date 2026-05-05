#!/usr/bin/env python3
"""
NDR System v6 - Intelligent Listener & Controller
Receives rich JSON alerts from C++ sensor, logs them to SQLite,
manages IP bans with automatic expiration.
"""

import socket
import os
import sys
import json
import sqlite3
import threading
import time
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

# ============== CONFIGURATION ==============
SOCK_PATH = "/tmp/ndr.sock"
DB_PATH = "/tmp/ndr_alerts.db"

# Ban policies: {severity: (duration_minutes, alert_count_threshold)}
BAN_POLICIES = {
    "INFO": (5, 10),           # 5 min ban if 10 INFO events in 1 min
    "WARNING": (10, 5),        # 10 min ban if 5 WARNING events
    "CRITICAL": (60, 2)        # 60 min ban if 2+ CRITICAL events
}

# ============== DATABASE SETUP ==============

def init_database():
    """Initialize SQLite database with required tables."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dest_port INTEGER,
                protocol TEXT,
                signature TEXT,
                additional_data TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # IP bans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_bans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT UNIQUE NOT NULL,
                ban_reason TEXT,
                ban_start DATETIME DEFAULT CURRENT_TIMESTAMP,
                ban_duration_minutes INTEGER NOT NULL,
                ban_end DATETIME NOT NULL,
                alert_count INTEGER DEFAULT 1,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        # Attack frequency tracking (for escalation)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_tracking (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT NOT NULL,
                alert_count INTEGER DEFAULT 1,
                window_start DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(src_ip)
            )
        ''')
        
        conn.commit()
        conn.close()
        print("[✓] Baza danych zainicjalizowana:", DB_PATH)
    except Exception as e:
        print(f"[ERROR] Błąd przy inicjalizacji bazy: {e}")
        sys.exit(1)


# ============== BAN MANAGEMENT ==============

def is_ip_banned(ip):
    """Check if IP is currently banned and active."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ban_end FROM ip_bans 
            WHERE src_ip = ? AND status = 'active' 
            AND ban_end > CURRENT_TIMESTAMP
        ''', (ip,))
        
        result = cursor.fetchone()
        conn.close()
        return result is not None
    except Exception as e:
        print(f"[ERROR] Błąd przy sprawdzeniu banu: {e}")
        return False


def add_ban(ip, reason, duration_minutes):
    """Add or update IP ban."""
    if ip == "127.0.0.1" or ip.startswith("192.168."):
        print(f"[SKIP] IP {ip} nie może być zbanowany (whitelist)")
        return False
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if already banned
        cursor.execute('''
            SELECT id, ban_duration_minutes, alert_count FROM ip_bans 
            WHERE src_ip = ? AND status = 'active'
        ''', (ip,))
        
        existing = cursor.fetchone()
        ban_end = (datetime.now() + timedelta(minutes=duration_minutes)).isoformat()
        
        if existing:
            ban_id, existing_duration, alert_count = existing
            # Escalate: increase ban duration
            new_duration = min(existing_duration + duration_minutes, 1440)  # max 24h
            new_alert_count = alert_count + 1
            
            cursor.execute('''
                UPDATE ip_bans 
                SET ban_duration_minutes = ?, 
                    ban_end = ?,
                    alert_count = ?,
                    ban_reason = ?
                WHERE id = ?
            ''', (new_duration, ban_end, new_alert_count, reason, ban_id))
            
            print(f"[ESCALATE] Ban na {ip} został przedłużony (licznik: {new_alert_count})")
        else:
            # New ban
            cursor.execute('''
                INSERT INTO ip_bans (src_ip, ban_reason, ban_duration_minutes, ban_end)
                VALUES (?, ?, ?, ?)
            ''', (ip, reason, duration_minutes, ban_end))
            
            print(f"[BAN] IP {ip} zbanowany na {duration_minutes} minut ({reason})")
            
            # Apply iptables rule (requires sudo or running as root)
            try:
                subprocess.run(
                    f"iptables -A INPUT -s {ip} -j DROP",
                    shell=True,
                    check=False,
                    capture_output=True
                )
            except Exception as e:
                print(f"[WARN] iptables może wymagać sudo: {e}")
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[ERROR] Błąd przy dodawaniu banu: {e}")
        return False


def remove_ban(ip):
    """Remove IP ban and iptables rule."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Mark as inactive
        cursor.execute('''
            UPDATE ip_bans SET status = 'inactive' WHERE src_ip = ?
        ''', (ip,))
        
        conn.commit()
        conn.close()
        
        # Remove iptables rule
        try:
            subprocess.run(
                f"iptables -D INPUT -s {ip} -j DROP",
                shell=True,
                check=False,
                capture_output=True
            )
            print(f"[UNBAN] IP {ip} rozbanowany i usunięty z iptables")
        except Exception as e:
            print(f"[WARN] Błąd przy usuwaniu reguły iptables: {e}")
        
        return True
    except Exception as e:
        print(f"[ERROR] Błąd przy usuwaniu banu: {e}")
        return False


def cleanup_expired_bans():
    """Check for expired bans and remove them."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT src_ip FROM ip_bans 
            WHERE status = 'active' AND ban_end < CURRENT_TIMESTAMP
        ''')
        
        expired_ips = cursor.fetchall()
        conn.close()
        
        for (ip,) in expired_ips:
            remove_ban(ip)
    except Exception as e:
        print(f"[ERROR] Błąd przy czyszczeniu banów: {e}")


# ============== ALERT PROCESSING ==============

def log_alert(alert_json):
    """Log alert to database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts 
            (timestamp, alert_type, severity, src_ip, dest_port, protocol, signature, additional_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert_json.get('timestamp', ''),
            alert_json.get('type', 'Unknown'),
            alert_json.get('severity_name', 'INFO'),
            alert_json.get('src_ip', ''),
            alert_json.get('dest_port', None),
            alert_json.get('protocol', ''),
            alert_json.get('signature', ''),
            json.dumps({k: v for k, v in alert_json.items() 
                       if k not in ['timestamp', 'type', 'severity', 'severity_name', 
                                   'src_ip', 'dest_port', 'protocol', 'signature']})
        ))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERROR] Błąd przy logowaniu alertu: {e}")


def track_attack_frequency(ip):
    """Track attack frequency for escalation."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get tracking window
        cursor.execute('''
            SELECT alert_count, window_start FROM attack_tracking 
            WHERE src_ip = ?
        ''', (ip,))
        
        result = cursor.fetchone()
        now = datetime.now()
        
        if result:
            count, window_start_str = result
            window_start = datetime.fromisoformat(window_start_str)
            
            # If window expired (>60s), reset
            if (now - window_start).total_seconds() > 60:
                cursor.execute('''
                    UPDATE attack_tracking 
                    SET alert_count = 1, window_start = ?
                    WHERE src_ip = ?
                ''', (now.isoformat(), ip))
                count = 1
            else:
                # Increment counter
                count += 1
                cursor.execute('''
                    UPDATE attack_tracking SET alert_count = ? WHERE src_ip = ?
                ''', (count, ip))
        else:
            # First attack in window
            cursor.execute('''
                INSERT INTO attack_tracking (src_ip, alert_count, window_start)
                VALUES (?, 1, ?)
            ''', (ip, now.isoformat()))
            count = 1
        
        conn.commit()
        conn.close()
        return count
    except Exception as e:
        print(f"[ERROR] Błąd przy śledzeniu ataków: {e}")
        return 1


def process_alert(alert_json):
    """
    Process incoming alert:
    1. Log to database
    2. Check escalation policies
    3. Manage bans
    """
    src_ip = alert_json.get('src_ip', 'unknown')
    severity = alert_json.get('severity_name', 'INFO')
    alert_type = alert_json.get('type', 'Unknown')
    
    # Log alert
    log_alert(alert_json)
    
    # Check if already banned
    if is_ip_banned(src_ip):
        print(f"[SKIP] IP {src_ip} już zbanowany, ignoruję powtarzające się alerty")
        return
    
    # Track frequency and check escalation
    attack_count = track_attack_frequency(src_ip)
    
    if severity in BAN_POLICIES:
        duration, threshold = BAN_POLICIES[severity]
        
        if attack_count >= threshold:
            reason = f"{alert_type} ({severity}) x{attack_count} w 60s"
            add_ban(src_ip, reason, duration)
    
    # Pretty print alert
    print(f"\n[ALERT ODEBRANY]")
    print(f"  Typ:      {alert_type}")
    print(f"  Poziom:   {severity}")
    print(f"  IP:       {src_ip}")
    print(f"  Port:     {alert_json.get('dest_port', 'N/A')}")
    print(f"  Protocol: {alert_json.get('protocol', 'N/A')}")
    print(f"  Sygnatura: {alert_json.get('signature', 'N/A')}")
    print(f"  Czas:     {alert_json.get('timestamp', 'N/A')}")
    print()


# ============== SOCKET LISTENER ==============

def setup_listener():
    """Setup Unix socket listener."""
    # Clean up old socket
    if os.path.exists(SOCK_PATH):
        os.remove(SOCK_PATH)
    
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCK_PATH)
    os.chmod(SOCK_PATH, 0o777)
    server.listen(1)
    
    return server


def listener_loop(server):
    """Main listener loop."""
    print(f"[*] Python Listener: Oczekiwanie na alerty na {SOCK_PATH}...\n")
    
    try:
        while True:
            try:
                conn, addr = server.accept()
                data = conn.recv(4096)
                
                if data:
                    try:
                        message = json.loads(data.decode('utf-8'))
                        
                        # Check message type
                        msg_type = message.get('type', 'alert')
                        
                        if msg_type == 'unban':
                            # Handle unban request
                            ip_to_unban = message.get('ip')
                            if ip_to_unban:
                                success = remove_ban(ip_to_unban)
                                response = {'success': success, 'ip': ip_to_unban}
                                conn.send(json.dumps(response).encode('utf-8'))
                            else:
                                conn.send(json.dumps({'success': False, 'error': 'No IP specified'}).encode('utf-8'))
                        else:
                            # Handle alert
                            process_alert(message)
                            
                    except json.JSONDecodeError:
                        print(f"[WARN] Nieprawidłowy JSON: {data.decode('utf-8', errors='ignore')}")
                
                conn.close()
            except Exception as e:
                print(f"[ERROR] Błąd w listener loop: {e}")
    except KeyboardInterrupt:
        print("\n[*] Zamykanie listenera...")


def ban_cleanup_loop():
    """Background thread to clean expired bans."""
    while True:
        time.sleep(30)  # Check every 30s
        cleanup_expired_bans()


# ============== STATISTICS ==============

def print_stats():
    """Print current system statistics."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Total alerts
        cursor.execute('SELECT COUNT(*) FROM alerts')
        total_alerts = cursor.fetchone()[0]
        
        # Active bans
        cursor.execute('''
            SELECT COUNT(*) FROM ip_bans 
            WHERE status = 'active' AND ban_end > CURRENT_TIMESTAMP
        ''')
        active_bans = cursor.fetchone()[0]
        
        # Top attacking IPs
        cursor.execute('''
            SELECT src_ip, COUNT(*) as count FROM alerts 
            GROUP BY src_ip ORDER BY count DESC LIMIT 5
        ''')
        top_ips = cursor.fetchall()
        
        conn.close()
        
        print("\n" + "="*50)
        print("  NDR System - Statistics")
        print("="*50)
        print(f"Łącznie alertów:     {total_alerts}")
        print(f"Aktywnie zbanowane:  {active_bans}")
        print("\nTop 5 atakujących IP:")
        for ip, count in top_ips:
            print(f"  {ip}: {count} zdarzeń")
        print("="*50 + "\n")
    except Exception as e:
        print(f"[ERROR] Błąd przy wyświetlaniu statystyk: {e}")


# ============== MAIN ==============

def main():
    print("================================")
    print("  NDR System v6 - Listener")
    print("  Rich JSON + SQLite + Bans")
    print("================================\n")
    
    # Initialize
    init_database()
    server = setup_listener()
    
    # Start background cleanup thread
    cleanup_thread = threading.Thread(target=ban_cleanup_loop, daemon=True)
    cleanup_thread.start()
    
    # Start stats thread (every 60s)
    def stats_loop():
        time.sleep(10)  # Initial delay
        while True:
            print_stats()
            time.sleep(60)
    
    stats_thread = threading.Thread(target=stats_loop, daemon=True)
    stats_thread.start()
    
    # Main listener
    try:
        listener_loop(server)
    except KeyboardInterrupt:
        print("\n[*] Zamykanie...")
    finally:
        server.close()
        if os.path.exists(SOCK_PATH):
            os.remove(SOCK_PATH)
        print("[*] Socket usunięty")


if __name__ == "__main__":
    main()
