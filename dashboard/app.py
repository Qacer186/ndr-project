#!/usr/bin/env python3
"""
NDR System - Dashboard Backend (Flask)
Serves real-time alerts and statistics from SQLite database
"""

from flask import Flask, render_template, jsonify, request
import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
import threading
import time

app = Flask(__name__, template_folder='templates', static_folder='static')

DB_PATH = "/tmp/ndr_alerts.db"

# ============== DATABASE HELPERS ==============

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def dict_from_row(row):
    return dict(row) if row else None

# ============== API ENDPOINTS ==============

@app.route('/api/stats')
def api_stats():
    """Get overall statistics"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Total alerts
        cursor.execute('SELECT COUNT(*) as count FROM alerts')
        total_alerts = cursor.fetchone()['count']
        
        # Active bans
        cursor.execute('''
            SELECT COUNT(*) as count FROM ip_bans 
            WHERE status = 'active' AND ban_end > CURRENT_TIMESTAMP
        ''')
        active_bans = cursor.fetchone()['count']
        
        # Alerts by severity
        try:
            cursor.execute('''
                SELECT severity, COUNT(*) as count 
                FROM alerts 
                GROUP BY severity
            ''')
            severity_stats = {row['severity']: row['count'] for row in cursor.fetchall()}
        except Exception as e:
            print(f"[ERROR] Severity query failed: {e}")
            severity_stats = {}
        
        # Top attacking IPs
        cursor.execute('''
            SELECT src_ip, COUNT(*) as count 
            FROM alerts 
            GROUP BY src_ip 
            ORDER BY count DESC 
            LIMIT 5
        ''')
        top_ips = [dict(row) for row in cursor.fetchall()]
        
        # Alerts by type
        try:
            cursor.execute('''
                SELECT alert_type, COUNT(*) as count 
                FROM alerts 
                GROUP BY alert_type
            ''')
            alert_types = {row['alert_type']: row['count'] for row in cursor.fetchall()}
        except Exception as e:
            print(f"[ERROR] Alert type query failed: {e}")
            alert_types = {}
        
        conn.close()
        
        return jsonify({
            'total_alerts': total_alerts,
            'active_bans': active_bans,
            'severity_stats': severity_stats,
            'top_ips': top_ips,
            'alert_types': alert_types
        })
    except Exception as e:
        print(f"[ERROR] API stats error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts')
def api_alerts():
    """Get recent alerts with pagination"""
    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 20, type=int)
        offset = (page - 1) * limit
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get total count
        cursor.execute('SELECT COUNT(*) as count FROM alerts')
        total = cursor.fetchone()['count']
        
        # Get alerts
        cursor.execute('''
            SELECT * FROM alerts 
            ORDER BY id DESC 
            LIMIT ? OFFSET ?
        ''', (limit, offset))
        
        alerts = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({
            'alerts': alerts,
            'total': total,
            'page': page,
            'pages': (total + limit - 1) // limit
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/bans')
def api_bans():
    """Get active IP bans"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT src_ip, ban_reason, ban_start, ban_end, alert_count, status
            FROM ip_bans 
            WHERE status = 'active'
            ORDER BY ban_start DESC
        ''')
        
        bans = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({'bans': bans})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/timeline')
def api_timeline():
    """Get alert timeline (last 24 hours)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get alerts per hour
        cursor.execute('''
            SELECT 
                strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
                COUNT(*) as count,
                severity_name
            FROM alerts
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY hour, severity_name
            ORDER BY hour
        ''')
        
        timeline = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({'timeline': timeline})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alert/<int:alert_id>')
def api_alert_detail(alert_id):
    """Get detailed information about specific alert"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM alerts WHERE id = ?', (alert_id,))
        alert = cursor.fetchone()
        conn.close()
        
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        return jsonify(dict(alert))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/unban/<ip>', methods=['POST'])
def api_unban(ip):
    """Manually unban an IP by sending request to listener"""
    try:
        import socket
        
        # Connect to listener socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect("/tmp/ndr.sock")
        
        # Send unban request
        unban_msg = json.dumps({
            'type': 'unban',
            'ip': ip
        })
        
        sock.send(unban_msg.encode('utf-8'))
        
        # Receive response
        response = sock.recv(1024)
        sock.close()
        
        result = json.loads(response.decode('utf-8'))
        
        if result.get('success'):
            return jsonify({'success': True, 'message': f'IP {ip} unbanned'})
        else:
            return jsonify({'success': False, 'error': result.get('error', 'Unknown error')})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============== WEB PAGES ==============

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/alerts')
def alerts_page():
    """Alerts list page"""
    return render_template('alerts.html')

@app.route('/bans')
def bans_page():
    """IP bans page"""
    return render_template('bans.html')

@app.route('/health')
def health():
    """Health check"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) as count FROM alerts')
        conn.close()
        return jsonify({'status': 'healthy', 'db': 'connected'})
    except:
        return jsonify({'status': 'unhealthy', 'db': 'disconnected'}), 500

if __name__ == '__main__':
    print("\n╔════════════════════════════════════╗")
    print("║  NDR Dashboard - Flask Backend    ║")
    print("╚════════════════════════════════════╝\n")
    
    print(f"[+] Database: {DB_PATH}")
    print("[+] Starting Flask server on http://127.0.0.1:5000\n")
    
    app.run(debug=False, host='127.0.0.1', port=5001, threaded=True)
