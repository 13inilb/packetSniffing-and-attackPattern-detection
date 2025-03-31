import os
import json
import threading
import sqlite3
import datetime
import subprocess
import pandas as pd
from scapy.all import sniff, wrpcap

# Database paths
PACKET_DB = "./packets.db"
ALERTS_DB = "./alerts.db"

# Lock for database operations
db_lock = threading.Lock()

# Protocol mapping
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    # Add more protocols as needed
}

def initialize_db():
    with db_lock:
        with sqlite3.connect(PACKET_DB) as conn:
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
        with sqlite3.connect(ALERTS_DB) as conn:
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

def insert_packet(timestamp, src_ip, dst_ip, protocol):
    protocol_name = PROTOCOL_MAP.get(int(protocol), f"Unknown ({protocol})")
    with db_lock, sqlite3.connect(PACKET_DB) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO packets (timestamp, src_ip, dst_ip, protocol)
            VALUES (?, ?, ?, ?)
        ''', (timestamp, src_ip, dst_ip, protocol_name))
        conn.commit()

def process_packet(packet):
    if packet.haslayer('IP'):
        timestamp = datetime.datetime.fromtimestamp(packet.time).isoformat()
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        protocol = packet.sprintf('%IP.proto%')
        insert_packet(timestamp, src_ip, dst_ip, protocol)

def capture_packets(pcap_file, interface, stop_event):
    sniffed_packets = sniff(
        iface=interface,
        prn=process_packet,
        store=True,
        stop_filter=lambda x: stop_event.is_set()
    )
    wrpcap(pcap_file, sniffed_packets)

def run_suricata(pcap_file, log_location="./suricata_logs/"):
    os.makedirs(log_location, exist_ok=True)
    suricata_cmd = [
        "suricata", "-c", "/etc/suricata/suricata.yaml",
        "-k", "none", "-r", pcap_file,
        "--runmode=autofp", "-l", log_location
    ]
    result = subprocess.run(suricata_cmd, capture_output=True, text=True)
    return result

def insert_alert(event):
    with db_lock, sqlite3.connect(ALERTS_DB) as conn:
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

def fetch_alerts():
    with db_lock, sqlite3.connect(ALERTS_DB) as conn:
        df = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC", conn)
 
