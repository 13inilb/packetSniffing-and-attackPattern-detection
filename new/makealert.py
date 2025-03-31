mport os
import sys
import json
import sqlite3
import subprocess

def initialize_db(db_path):
    if not os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                src_port TEXT,
                dest_ip TEXT,
                dest_port TEXT,
                protocol TEXT,
                alert TEXT
            )
        ''')
        conn.commit()
        conn.close()

def insert_alert(db_path, timestamp, src_ip, src_port, dest_ip, dest_port, protocol, alert):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (timestamp, src_ip, src_port, dest_ip, dest_port, protocol, alert)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, src_ip, src_port, dest_ip, dest_port, protocol, alert))
    conn.commit()
    conn.close()

def run_suricata(pcap_file, log_location="./suricata/"):
    db_path = "./alerts.db"
    initialize_db(db_path)
    
    if not os.path.isfile(pcap_file):
        print(f"File {pcap_file} doesn't seem to be there - please supply a valid pcap file.")
        sys.exit(1)
    
    if not os.path.exists(log_location):
        print("Attempting to create Suricata log directory...")
        os.makedirs(log_location)
    else:
        print("Log location exists, removing previous content...")
        for file in os.listdir(log_location):
            os.remove(os.path.join(log_location, file))
    
    print("Running Suricata in offline mode...")
    suricata_cmd = [
        "suricata", "-c", "/etc/suricata/suricata.yaml", "-k", "none", "-r", pcap_file,
        "--runmode=autofp", "-l", log_location
    ]
    
    result = subprocess.run(suricata_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print("Suricata encountered an error:", result.stderr)
        sys.exit(1)
    
    print("\nAlerts:\n")
    eve_json_path = os.path.join(log_location, "eve.json")
    
    if os.path.exists(eve_json_path):
        with open(eve_json_path, "r") as eve_file:
            for line in eve_file:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    timestamp = event['timestamp']
                    src_ip = event.get('src_ip', 'N/A')
                    src_port = event.get('src_port', 'N/A')
                    dest_ip = event.get('dest_ip', 'N/A')
                    dest_port = event.get('dest_port', 'N/A')
                    protocol = event.get('proto', 'N/A')
                    alert = event['alert']['signature']
                    
                    print(f"{timestamp} | {src_ip}:{src_port} -> {dest_ip}:{dest_port} | {protocol} | {alert}")
                    insert_alert(db_path, timestamp, src_ip, src_port, dest_ip, dest_port, protocol, alert)
    else:
        print("No alerts found in eve.json")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <pcapfile>")
        sys.exit(1)
    
    run_suricata(sys.argv[1])
