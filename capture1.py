from scapy.all import sniff, Ether, IP
import time
import socket
import sqlite3


# database creation
conn = sqlite3.connect("packetsdatabase.db", detect_types=sqlite3.PARSE_DECLTYPES)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    length INTEGER,
    payload TEXT,
    snort_status TEXT
)
""")
conn.commit()
conn.close()


# scapy function
def packet_handler(packet):
    #inform about the captured packet
    if packet.haslayer(IP):
        print(f"[+] packet captured from {packet['IP'].src} --> to {packet['IP'].dst}")
        src_port = packet.sport if packet.haslayer('TCP') or packet.haslayer('UDP') else None
        dst_port = packet.dport if packet.haslayer('TCP') or packet.haslayer('UDP') else None
        
        packet_data = {
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": packet.proto,
            "length": len(packet),
            "payload": str(packet.payload),
            "snort_status": "pending"
        }
    # Store data in the database 
        scapy_store_packet(packet_data)            
    


# store data from scapy
def scapy_store_packet(packet_data):
    conn = sqlite3.connect("packetsdatabase.db", detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol, length, payload, snort_status)
    VALUES (:src_ip, :dst_ip, :src_port, :dst_port, :protocol, :length, :payload, :snort_status )
    """, packet_data)
    conn.commit()
    conn.close()


def get_system_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("1.1.1.1", 80))
        return s.getsockname()[0]


def print_database():
    conn = sqlite3.connect("packetsdatabase.db", detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    cursor.execute("""select * from packets""")
    rows = cursor.fetchall()
    headings = [description[0] for description in cursor.description]   
    print("\t".join(headings))

    for row in rows:
        print("\t".join(str(item) if item is not None else 'NULL' for item in row))
    conn.commit()
    conn.close()


def main():
    sys_ip = get_system_ip()
    print(f"Sniffing started....")
    print(f"Listening for incoming packets on IP: {sys_ip}")

    try:
        sniff(prn=packet_handler, store=False )

        
    except KeyboardInterrupt:
        print(f"\nPacket capture stopped")
        

if __name__ == "__main__":   
    main() 

