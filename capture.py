from scapy.all import sniff, PcapWriter
import sqlite3


# Initialize database
conn = sqlite3.connect("packets.db")
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        protocol TEXT,
        status TEXT,
        analysis TEXT
    )
""")
conn.commit()


def process_packet(packet, pcap_writer):
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        protocol = packet.sprintf('%IP.proto%')

        cursor.execute("INSERT INTO packets (timestamp, src_ip, dst_ip, protocol ) VALUES (datetime('now'), ?, ?, ?)",
                       (src_ip, dst_ip, protocol))
        conn.commit()
        print(f"Captured: {src_ip} -> {dst_ip} ({protocol})")
        pcap_writer.write(packet)


def capture(pcap_file):
    with PcapWriter(pcap_file, append=True, sync=True) as pcap_writer:
        sniff(prn=lambda pkt: process_packet(pkt, pcap_writer), store=False, count = 50)


def main():
    pcap_file = "captured.pcap"
    capture(pcap_file)
