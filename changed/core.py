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
            # Add more protocols as needed
        }
        self.initialize_db()

    def initialize_db(self):
        with self.db_lock:
            with sqlite3.connect(self.PACKET_DB) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        src_ip TEXT,
                        dst_ip TEXT,
                        protocol TEXT
                    )
                ''')
                conn.commit()
            with sqlite3.connect(self.ALERTS_DB) as conn:
                cursor = conn.cursor()
                cursor.execute('''
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
                conn.commit()

    def insert_packet(self, timestamp, src_ip, dst_ip, protocol):
        try:
            protocol_int = int(protocol)
            protocol_name = self.PROTOCOL_MAP.get(protocol_int, f"Unknown ({protocol})")
        except ValueError:
            protocol_name = protocol
            
        with self.db_lock, sqlite3.connect(self.PACKET_DB) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO packets (timestamp, src_ip, dst_ip, protocol)
                VALUES (?, ?, ?, ?)
            ''', (timestamp, src_ip, dst_ip, protocol_name))
            conn.commit()

    def process_packet(self, packet):
        if packet.haslayer('IP'):
            timestamp = datetime.datetime.fromtimestamp(packet.time).isoformat()
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            protocol = packet['IP'].proto
            self.insert_packet(timestamp, src_ip, dst_ip, protocol)

    def start_capture(self, pcap_file, interface, stop_event):
        def packet_handler(packet):
            self.process_packet(packet)
            
        sniffed_packets = sniff(
            iface=interface,
            prn=packet_handler,
            store=True,
            stop_filter=lambda x: stop_event.is_set()
        )
        wrpcap(pcap_file, sniffed_packets)
        return True

    def analyze_pcap(self, pcap_file, log_location="./suricata_logs/"):
        os.makedirs(log_location, exist_ok=True)
        suricata_cmd = [
            "sudo", "suricata", "-c", "/etc/suricata/suricata.yaml",
            "-k", "none", "-r", pcap_file,
            "--runmode=autofp", "-l", log_location
        ]
        result = subprocess.run(suricata_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            eve_json_path = os.path.join(log_location, "eve.json")
            if os.path.exists(eve_json_path):
                with open(eve_json_path, "r") as eve_file:
                    for line in eve_file:
                        event = json.loads(line)
                        if event.get("event_type") == "alert":
                            self.insert_alert(event)
                return True, "Analysis completed"
            return False, "No alerts found"
        return False, result.stderr

    def insert_alert(self, event):
        with self.db_lock, sqlite3.connect(self.ALERTS_DB) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alerts (timestamp, src_ip, src_port, dest_ip, dest_port, protocol, alert)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                event['timestamp'],
                event.get('src_ip', 'N/A'),
                event.get('src_port', 'N/A'),
                event.get('dest_ip', 'N/A'),
                event.get('dest_port', 'N/A'),
                event.get('proto', 'N/A'),
                event['alert']['signature']
            ))
            conn.commit()

    def get_alerts(self, limit=100):
        with self.db_lock, sqlite3.connect(self.ALERTS_DB) as conn:
            df = pd.read_sql_query(
                f"SELECT * FROM alerts ORDER BY timestamp DESC LIMIT {limit}", 
                conn
            )
        return df

    def get_packets(self, limit=100):
        with self.db_lock, sqlite3.connect(self.PACKET_DB) as conn:
            df = pd.read_sql_query(
                f"SELECT * FROM packets ORDER BY timestamp DESC LIMIT {limit}", 
                conn
            )
        return df
