import threading
from scapy.all import sniff, wrpcap,  Ether, IP
import time
import socket

packets =[]

def packet_handler(packet):
        #inform about the captured packet
        if packet.haslayer('IP'):
            print(f"[+] packet captured from {packet['IP'].src} --> to {packet['IP'].dst}")

        packets.append(packet)  # Append the packet to the list

        
def save_pcap():
    global packets
    while True:
        if packets:
            wrpcap("captured_packets.pcap", packets, append=True)  # Append packets
            print(f"Saved {len(packets)} packets to 'captured_packets.pcap'")
            packets = []  # Clear packet list after saving
        time.sleep(2)  # Delay for 2 seconds

def get_system_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("1.1.1.1", 80))
        return s.getsockname()[0]



def main():
    sys_ip = get_system_ip()
    print(f"Sniffing started....")
    print(f"Listening for incoming packets on IP: {sys_ip}")

    dummy_packet = Ether() / IP(dst="0.0.0.0")
    wrpcap("captured_packets.pcap", dummy_packet)  # Create file with a dummy packet

    try:
        threading.Thread(target=save_pcap, daemon=True).start()
        sniff(prn=packet_handler, filter=f"dst host {sys_ip}", store=False )
        
    except KeyboardInterrupt:
            print(f"\nPacket capture stopped")
        

    
    

if __name__ == "__main__":   
    main() 
