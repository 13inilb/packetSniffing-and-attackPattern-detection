from scapy.all import sniff
import subprocess
import sqlite3
from datetime import datetime
import socket

# Register datetime adapter and converter for SQLite
sqlite3.register_adapter(datetime, lambda dt: dt.isoformat())
sqlite3.register_converter("timestamp", lambda s: datetime.fromisoformat(s.decode()))

# Protocol mapping 
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

# Database Connection Setup
conn = sqlite3.connect("packets.db", detect_types=sqlite3.PARSE_DECLTYPES)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP,
    src_ip TEXT,
    dst_ip TEXT,
    protocol TEXT,
    payload TEXT,
    snort_status TEXT
)
""")
conn.commit()

# Packet storage for batching
packet_batch = []
BATCH_SIZE = 10

# Analyze packets with Snort (batch input)
def analyze_with_snort(packet_data):
    try:
        result = subprocess.run(
            ["sudo", "snort", "-A", "console", "-c", "/etc/snort/snort.conf", "-Q"],
            input=packet_data,
            text=True,
            capture_output=True
        )
        return [
            "POSSIBLE DANGER" if "alert" in result.stdout.lower() else "SAFE"
            for _ in packet_data.split("\n") if _
        ]
    except Exception as e:
        return ["Error"] * len(packet_data.split("\n"))

# Insert packets into the database
def insert_into_database(batch, snort_results):
    for i, packet in enumerate(batch):
        cursor.execute("""
            INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, payload, snort_status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            packet['timestamp'],
            packet['src_ip'],
            packet['dst_ip'],
            packet['protocol'],
            packet['payload'],
            snort_results[i]
        ))
    conn.commit()

# Process each packet
def packet_callback(packet):
    if packet.haslayer('IP'):
        packet_info = {
            "timestamp": datetime.now(),
            "src_ip": packet['IP'].src,
            "dst_ip": packet['IP'].dst,
            "protocol": PROTOCOL_MAP.get(packet['IP'].proto, f"Unknown ({packet['IP'].proto})"),
            "payload": str(packet['Raw'].load) if packet.haslayer('Raw') else "N/A"
        }

        packet_batch.append(packet_info)

        # Process in batches for better performance
        if len(packet_batch) >= BATCH_SIZE:
            packet_data = "\n".join([str(pkt) for pkt in packet_batch])
            snort_results = analyze_with_snort(packet_data)
            insert_into_database(packet_batch, snort_results)

            for i, pkt in enumerate(packet_batch):
                print(f"[+] {pkt['src_ip']} -> {pkt['dst_ip']} | Protocol: {pkt['protocol']} | Status: {snort_results[i]}")

            packet_batch.clear()

# Get the ip of the system
def get_system_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("1.1.1.1", 80))
        return s.getsockname()[0]

sys_ip = get_system_ip()
print(f"Listening for incoming packets on IP: {sys_ip}")


# Start packet sniffing
print("[*] Starting batch packet capture ...")
sniff(prn=packet_callback, filter=f"dst host {sys_ip}", store=False)
