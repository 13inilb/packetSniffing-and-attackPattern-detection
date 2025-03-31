import os
import json
import threading
import sqlite3
import datetime
import subprocess
import pandas as pd
from scapy.all import sniff, wrpcap

class PacketAnalyzer:
    def __init__(self):
        self.PACKET_DB = "./packets.db"
        self.ALERTS_DB = "./alerts.db"
        self.db_lock = threading.Lock()
        self.PROTOCOL_MAP = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
        }
        self._initialize_databases()

    def _initialize_databases(self):
        with self.db_lock:
            # Initialize packets database
            with sqlite3.connect(self.PACKET_DB) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        src_ip TEXT,
                        dst_ip TEXT,
                        protocol TEXT
                    )
                ''')
            
            # Initialize alerts database
            with sqlite3.connect(self.ALERTS_DB) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        src_ip TEXT,
                        src_port TEXT,
                        dest_ip TEXT,
                        dest_port TEXT,
                        protocol TEXT,
                        alert TEXT
                    )
                ''')

    def _insert_packet(self, packet):
        if not packet.haslayer('IP'):
            return

        timestamp = datetime.datetime.fromtimestamp(packet.time).isoformat()
        proto = packet.sprintf('%IP.proto%')
        
        with self.db_lock, sqlite3.connect(self.PACKET_DB) as conn:
            conn.execute('''
                INSERT INTO packets (timestamp, src_ip, dst_ip, protocol)
                VALUES (?, ?, ?, ?)
            ''', (
                timestamp,
                packet['IP'].src,
                packet['IP'].dst,
                self.PROTOCOL_MAP.get(int(proto), f"Unknown ({proto})")
            ))

    def start_capture(self, interface, stop_event):
        def packet_handler(packet):
            self._insert_packet(packet)
        
        sniff(
            iface=interface,
            prn=packet_handler,
            store=False,
            stop_filter=lambda _: stop_event.is_set()
        )

    def analyze_pcap(self, pcap_file):
        log_dir = "./suricata_logs"
        os.makedirs(log_dir, exist_ok=True)
        
        try:
            result = subprocess.run(
                ["suricata", "-r", pcap_file, "-l", log_dir],
                capture_output=True,
                text=True,
                check=True
            )
            
            eve_file = os.path.join(log_dir, "eve.json")
            if os.path.exists(eve_file):
                with open(eve_file) as f:
                    for line in f:
                        alert = json.loads(line)
                        if alert.get('event_type') == 'alert':
                            self._store_alert(alert)
                return True, "Analysis completed successfully"
            return False, "No alerts generated"
        
        except subprocess.CalledProcessError as e:
            return False, f"Suricata error: {e.stderr}"

    def _store_alert(self, alert):
        with self.db_lock, sqlite3.connect(self.ALERTS_DB) as conn:
            conn.execute('''
                INSERT INTO alerts (
                    timestamp, src_ip, src_port, 
                    dest_ip, dest_port, protocol, alert
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert['timestamp'],
                alert.get('src_ip', 'N/A'),
                alert.get('src_port', 'N/A'),
                alert.get('dest_ip', 'N/A'),
                alert.get('dest_port', 'N/A'),
                alert.get('proto', 'N/A'),
                alert['alert']['signature']
            ))

    def get_alerts(self, limit=100):
        with self.db_lock, sqlite3.connect(self.ALERTS_DB) as conn:
            return pd.read_sql(f'''
                SELECT * FROM alerts 
                ORDER BY timestamp DESC 
                LIMIT {limit}
            ''', conn)

    def get_packets(self, limit=100):
        with self.db_lock, sqlite3.connect(self.PACKET_DB) as conn:
            return pd.read_sql(f'''
                SELECT * FROM packets 
                ORDER BY timestamp DESC 
                LIMIT {limit}
            ''', conn)
