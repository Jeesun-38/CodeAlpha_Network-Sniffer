import scapy.all as scapy
import sqlite3
import argparse
from datetime import datetime

def create_database():
    conn = sqlite3.connect("network_traffic.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            length INTEGER,
            raw_data TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_packet(packet):
    conn = sqlite3.connect("network_traffic.db")
    cursor = conn.cursor()
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "N/A"
    dst_ip = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "N/A"
    protocol = packet[scapy.IP].proto if packet.haslayer(scapy.IP) else "N/A"
    length = len(packet)
    raw_data = str(packet.summary())
    
    cursor.execute("INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length, raw_data) VALUES (?, ?, ?, ?, ?, ?)",
                   (timestamp, src_ip, dst_ip, protocol, length, raw_data))
    conn.commit()
    conn.close()

def packet_handler(packet):
    if packet.haslayer(scapy.IP):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {packet[scapy.IP].src} -> {packet[scapy.IP].dst} | Protocol: {packet[scapy.IP].proto} | Length: {len(packet)}")
        log_packet(packet)

def sniff_traffic(interface, port_choice):
    port_filters = {
        "1": "port 80",   # HTTP
        "2": "port 443",  # HTTPS
        "3": "port 21",   # FTP
        "4": "port 22",   # SSH
        "5": "port 53",   # DNS
        "6": "port 25",   # SMTP
        "7": "port 110"   # POP3
    }
    
    filter_rule = port_filters.get(port_choice, "")
    print(f"[*] Starting network sniffer on {interface} with filter: {filter_rule if filter_rule else 'No filter'}")
    scapy.sniff(iface=interface, filter=filter_rule, prn=packet_handler, store=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Network Sniffer")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on (e.g., eth0, wlan0)")
    parser.add_argument("-p", "--port", required=True, help="Choose port: 1) HTTP 2) HTTPS 3) FTP 4) SSH 5) DNS 6) SMTP 7) POP3")
    args = parser.parse_args()
    
    create_database()
    sniff_traffic(args.interface, args.port)
