import streamlit as st
import subprocess
import sqlite3
from streamlit_autorefresh import st_autorefresh
import pandas as pd

st.set_page_config(
    page_title="Network Analyzer" 
)

# Custom CSS for gradient glass background effect with white text and red metric number
background_style = """
<style>
    .stApp {
        background: linear-gradient(135deg, rgba(255,255,255,0.1), rgba(255,255,255,0));
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        background-color: rgba(98, 114, 164, 0.3);
        border: 1px solid rgba(255, 255, 255, 0.18);
        box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
    }
    
    .stApp::before {
        content: "";
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: linear-gradient(135deg, #6e48aa 0%, #9d50bb 50%, #6e48aa 100%);
        z-index: -1;
    }
    
    /* Make dataframes and other elements semi-transparent */
    div[data-testid="stDataFrame"] {
        background: rgba(255, 255, 255, 0.2) !important;
        border-radius: 12px;
        backdrop-filter: blur(5px);
        border: 1px solid rgba(255, 255, 255, 0.18);
    }
    
    div.stButton > button {
        background: rgba(255, 255, 255, 0.2);
        border: 1px solid rgba(255, 255, 255, 0.18);
        border-radius: 6px;
        backdrop-filter: blur(5px);
        transition: all 0.3s ease;
    }
    
    div.stButton > button:hover {
        background: rgba(255, 255, 255, 0.3);
        box-shadow: 0 4px 12px rgba(31, 38, 135, 0.3);
    }
    
    .stMetric {
        background: rgba(255, 255, 255, 0.2);
        border-radius: 12px;
        padding: 10px;
        backdrop-filter: blur(5px);
        border: 1px solid rgba(255, 255, 255, 0.18);
    }
    
    /* White text for titles and headers */
    h1, h2, h3, h4, h5, h6 {
        color: white !important;
        text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
    }
    
    /* Make title text more visible */
    .main-header {
        font-weight: 600;
    }
    
    /* Ensure metric labels are white */
    .stMetric label {
        color: white !important;
    }
    
    /* Make metric value red */
    .stMetric [data-testid="stMetricValue"] {
        color: #ff3b5c !important;
        font-weight: bold;
        text-shadow: 0 1px 2px rgba(0, 0, 0, 0.2);
    }
</style>
"""

# Including custom CSS with markdown
st.markdown(background_style, unsafe_allow_html=True)

st.markdown('<h1 class="main-header">Network Packet Capture and Analyzer</h1>', unsafe_allow_html=True)

DB_PATH = "./packets.db"
AL_PATH = "./alerts.db"

# Auto-refresh every 5 seconds
st_autorefresh(interval=5000, key="data_refresh")

if "process" not in st.session_state:
    st.session_state.process = None

# Function to get live data with caching disabled
@st.cache_data(ttl=5)  # Ensures new data is fetched every 5 seconds
def getdatabase():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql("SELECT * FROM packets ORDER BY timestamp DESC", conn)
    conn.close()
    return df

@st.cache_data(ttl=5)  
def getalertdatabase():
    conn = sqlite3.connect(AL_PATH)
    al = pd.read_sql("SELECT * FROM alerts ORDER BY timestamp DESC", conn)  
    conn.close()
    return al

# Function to start capture process
def startcapture():
    if st.session_state.process is None:
        st.session_state.process = subprocess.Popen(
            ["sudo", "python3", "./capture.py"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        st.success("Started Capturing")

# Function to stop capture process
def stopcapture():
    if st.session_state.process:
        st.session_state.process.terminate()  # Send termination signal
        st.session_state.process = None
        st.warning("Stopped Capturing")

def analyze():
    if st.session_state.process is None:
        st.session_state.process = subprocess.Popen(
            ["sudo", "python3", "./makealert.py", "captured.pcap"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        st.success("Analyzed Packets")

def cleardatabase():
    if st.session_state.process is None:
        conn = sqlite3.connect(AL_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM alerts")
        conn.commit()
        conn.close()

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM packets")
        conn.commit()
        conn.close()


# Create a layout with two columns for the header section
col1, col2 = st.columns([3, 1])

# Place the buttons in the first column
with col1:
    # Start & Stop Buttons
    if st.button("Start Capture"):
        startcapture()
    if st.button("Stop Capture"):
        stopcapture()
        analyze()

# Get alert data
al = getalertdatabase()

# Place the alert count box in the second column
with col2:
    st.metric(label="Alert Count", value=len(al))

# Add heading for Packets table
st.subheader("Network Packets")
# Fetch and display latest data from packets database
df = getdatabase()
st.dataframe(df)

# Add heading for Alerts table
st.subheader("Security Alerts")
# Display alerts data
st.dataframe(al)

with col1:
    if st.button("Clear data"):
        cleardatabase()
