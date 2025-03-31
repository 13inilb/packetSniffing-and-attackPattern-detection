import streamlit as st
from streamlit_autorefresh import st_autorefresh
import threading
import pandas as pd
from core import PacketAnalyzer

def main():
    st.title("Network Packet Capture and Analysis Dashboard")
    
    # Initialize the packet analyzer
    if 'analyzer' not in st.session_state:
        st.session_state.analyzer = PacketAnalyzer()
    
    # Interface selection
    interface = st.sidebar.text_input("Network Interface", "enp0s8")
    
    # Control buttons
    col1, col2, col3 = st.sidebar.columns(3)
    with col1:
        if st.button("Start Capture"):
            if 'stop_event' not in st.session_state:
                st.session_state.stop_event = threading.Event()
                st.session_state.stop_event.clear()
                
                st.session_state.pcap_file = "captured.pcap"
                st.session_state.capture_thread = threading.Thread(
                    target=st.session_state.analyzer.start_capture,
                    args=(st.session_state.pcap_file, interface, st.session_state.stop_event)
                )
                st.session_state.capture_thread.start()
                st.success("Packet capture started!")
    
    with col2:
        if st.button("Stop Capture"):
            if 'stop_event' in st.session_state:
                st.session_state.stop_event.set()
                st.warning("Stopping capture...")
    
    with col3:
        if st.button("Analyze PCAP"):
            if 'pcap_file' in st.session_state:
                success, message = st.session_state.analyzer.analyze_pcap(st.session_state.pcap_file)
                if success:
                    st.success("Suricata analysis completed!")
                else:
                    st.error(f"Suricata error: {message}")
            else:
                st.error("No capture file available!")

    # Display packet information
    st.subheader("Captured Packets")
    packets_df = st.session_state.analyzer.get_packets()
    st.dataframe(packets_df, height=300)

    # Auto-refresh alerts
    st_autorefresh(interval=5000, key="alerts_refresh")
    st.subheader("Security Alerts")
    alerts_df = st.session_state.analyzer.get_alerts()
    st.dataframe(alerts_df, height=400)

if __name__ == "__main__":
    main()
