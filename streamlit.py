import streamlit as st
import sqlite3
import pandas as pd
from scapy.all import rdpcap
import os

# Database Connection
conn = sqlite3.connect("packets.db")
cursor = conn.cursor()

# Protocol Mapping
PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

# Dashboard
st.title("Pkt_Project SIEM Dashboard")

# Overview
total_packets = cursor.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
threat_count = cursor.execute("SELECT COUNT(*) FROM packets WHERE snort_status = 'POSSIBLE DANGER'").fetchone()[0]

st.metric("Total Packets", total_packets)
st.metric("Threats Detected", threat_count)

# Packet Table
df = pd.read_sql("SELECT id, timestamp, src_ip, dst_ip, protocol, snort_status FROM packets", conn)
st.dataframe(df)

# Detailed View
packet_id = st.number_input("Enter Packet ID for Detailed Analysis", min_value=1)

if st.button("Show Details"):
    cursor.execute("SELECT pcap_file FROM packets WHERE id = ?", (packet_id,))
    pcap_file = cursor.fetchone()

    if pcap_file:
        packets = rdpcap(pcap_file[0])
        for pkt in packets:
            if pkt.haslayer('IP'):
                st.write(f"**Source IP:** {pkt['IP'].src}")
                st.write(f"**Destination IP:** {pkt['IP'].dst}")
                st.write(f"**Protocol:** {PROTOCOL_MAP.get(pkt['IP'].proto, 'Unknown')}")
                st.write(f"**Payload:** {pkt['Raw'].load if pkt.haslayer('Raw') else 'N/A'}")
                st.markdown("---")
    else:
        st.error("No data found for this packet ID.")
