import streamlit as st
import threading
import time
from core import PacketAnalyzer

def main():
    st.set_page_config(page_title="Network Monitor", layout="wide")
    st.title("Network Traffic Analyzer")
    
    # Initialize analyzer
    if 'analyzer' not in st.session_state:
        st.session_state.analyzer = PacketAnalyzer()
        st.session_state.capture_active = False
        st.session_state.stop_event = threading.Event()

    # Sidebar controls
    with st.sidebar:
        st.header("Configuration")
        interface = st.text_input("Network Interface", "eth0")
        refresh_rate = st.slider("Refresh Rate (seconds)", 1, 60, 5)
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Start Capture") and not st.session_state.capture_active:
                st.session_state.stop_event.clear()
                st.session_state.capture_thread = threading.Thread(
                    target=st.session_state.analyzer.start_capture,
                    args=(interface, st.session_state.stop_event)
                )
                st.session_state.capture_thread.start()
                st.session_state.capture_active = True
                st.success("Capture started!")
        
        with col2:
            if st.button("Stop Capture") and st.session_state.capture_active:
                st.session_state.stop_event.set()
                st.session_state.capture_thread.join()
                st.session_state.capture_active = False
                st.warning("Capture stopped")

        if st.button("Analyze Traffic"):
            pcap_path = "./capture.pcap"
            success, message = st.session_state.analyzer.analyze_pcap(pcap_path)
            if success:
                st.success(message)
            else:
                st.error(message)

    # Auto-refresh logic
    if 'refresh_count' not in st.session_state:
        st.session_state.refresh_count = 0
    
    if st.session_state.capture_active:
        time.sleep(refresh_rate)
        st.session_state.refresh_count += 1
        st.experimental_rerun()

    # Display tabs
    tab1, tab2 = st.tabs(["Alerts", "Packet Log"])
    
    with tab1:
        st.subheader("Security Alerts")
        alerts_df = st.session_state.analyzer.get_alerts()
        if not alerts_df.empty:
            st.dataframe(alerts_df, use_container_width=True)
        else:
            st.info("No security alerts detected")

    with tab2:
        st.subheader("Captured Packets")
        packets_df = st.session_state.analyzer.get_packets()
        if not packets_df.empty:
            st.dataframe(packets_df, use_container_width=True)
        else:
            st.info("No packets captured yet")

if __name__ == "__main__":
    main()
