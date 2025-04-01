import datetime
from scapy.all import sniff, PcapWriter, TCP, UDP
import sqlite3


# Initialize database
conn = sqlite3.connect("packets.db")
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        src_port INTEGER,
        dst_ip TEXT,
        dst_port INTEGER,
        protocol TEXT
    )
""")
conn.commit()

def process_packet(packet, pcap_writer):
    if packet.haslayer('IP'):
        timestamp = datetime.datetime.fromtimestamp(packet.time)
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
#       if (src_ip != "127.0.0.53") and (dst_ip != "127.0.0.53"): for avoiding local dns resolve
        protocol = packet.sprintf('%IP.proto%')

        src_port, dst_port = None, None

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = "TCP" 
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"  

        cursor.execute("INSERT INTO packets (timestamp, src_ip, src_port, dst_ip, dst_port,  protocol ) VALUES (?, ?, ?, ?, ?, ?)",
                       (timestamp, src_ip, src_port, dst_ip, dst_port, protocol))

        conn.commit()
        print(f"Captured: {src_ip} -> {dst_ip} ({protocol})")
        pcap_writer.write(packet)


def capture(pcap_file):
    with PcapWriter(pcap_file, append=True, sync=True) as pcap_writer:
        sniff(iface = "enp0s3",prn=lambda pkt: process_packet(pkt, pcap_writer), store=False )


def main():

    pcap_file = "captured.pcap"
    print("Starting Capture...")
    capture(pcap_file)

if __name__ == "__main__":   
    main() 
