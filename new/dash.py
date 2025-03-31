import streamlit as st
from streamlit_autorefresh import st_autorefresh
import threading
from core import initialize_db, capture_packets, run_suricata, fetch_alerts

def main():
    st.title("Network Packet Capture and Analysis Dashboard")
    initialize_db()

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
                    target=capture_packets,
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
                result = run_suricata(st.session_state.pcap_file)
                if result.returncode == 0:
                    st.success("Suricata analysis completed!")
                else:
                    st.error(f"Suricata error: {result.stderr}")
            else:
                st.error("No capture file available!")

    # Auto-refresh alerts
    st_autorefresh(interval=5000, key="alerts_refresh")
    st.subheader("Security Alerts")
    alerts_df = fetch_alerts()
    st.dataframe(alerts_df, height=400)

if __name__ == "__main__":
    main()
