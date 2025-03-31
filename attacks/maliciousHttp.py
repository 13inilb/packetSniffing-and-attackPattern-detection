#only for demonstration , use in a controlled environment only !!!!!!

from scapy.all import IP, TCP, Raw, send

target_ip = "192.168.56.103"

http_payload = "GET /evil.php?cmd=whoami HTTP/1.1\r\nHost: victim.com\r\n\r\n"

pkt = IP(dst = target_ip)/TCP(dport=80, flags="PA")/Raw(load=http_payload)
send(pkt, verbose=False)

print("Suspicious HTTP request sent!")
