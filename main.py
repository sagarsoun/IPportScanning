import streamlit as st
import socket
import ipaddress
import pandas as pd
import time
import json
import os
from datetime import datetime

st.set_page_config(page_title="IP Port Scanner", layout="wide")

if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []

def check_port(ip, port, timeout=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0

def scan_ip(ip, ports, progress_bar=None, timeout=1):
    open_ports = []
    total_ports = len(ports)
    
    for i, port in enumerate(ports):
        if progress_bar:
            progress_bar.progress((i + 1) / total_ports)
        
        if check_port(ip, port, timeout):
            service = get_service_name(port)
            open_ports.append({"port": port, "service": service})
    
    return open_ports

def get_service_name(port):
    common_ports = {
        20: "FTP-data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP (submission)",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP Alternate",
        8443: "HTTPS Alternate"
    }
    return common_ports.get(port, "Unknown")

def save_scan_results(results, filename):
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    return True

def load_scan_history():
    history_file = "scan_history.json"
    if os.path.exists(history_file):
        with open(history_file, 'r') as f:
            return json.load(f)
    return []

def save_scan_history(history):
    history_file = "scan_history.json"
    with open(history_file, 'w') as f:
        json.dump(history, f, indent=4)

st.title("IP Port Scanner")
st.markdown("---")

st.sidebar.header("Scan Options")

scan_type = st.sidebar.radio(
    "Select Scan Type",
    ["Single IP", "IP Range", "Multiple IPs"]
)

port_option = st.sidebar.radio(
    "Port Selection",
    ["Common Ports", "Port Range", "Specific Ports"]
)

timeout = st.sidebar.slider("Timeout (seconds)", 0.1, 5.0, 1.0, 0.1)

with st.container():
    st.subheader("Target Configuration")
    
    if scan_type == "Single IP":
        ip_address = st.text_input("Enter IP Address", "127.0.0.1")
        target_ips = [ip_address] if ip_address else []
    
    elif scan_type == "IP Range":
        col1, col2 = st.columns(2)
        start_ip = col1.text_input("Start IP Address", "192.168.1.1")
        end_ip = col2.text_input("End IP Address", "192.168.1.10")
        
        try:
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            target_ips = [str(ipaddress.IPv4Address(ip)) for ip in range(int(start), int(end) + 1)]
            st.info(f"IP Range: {len(target_ips)} addresses")
        except Exception as e:
            st.error(f"Invalid IP range: {e}")
            target_ips = []
    
    elif scan_type == "Multiple IPs":
        ip_list = st.text_area("Enter IP Addresses (one per line)")
        target_ips = [ip.strip() for ip in ip_list.split('\n') if ip.strip()]
    
    if port_option == "Common Ports":
        common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
        selected_ports = st.multiselect(
            "Select Common Ports",
            common_ports,
            default=[80, 443, 22, 3389]
        )
        ports_to_scan = selected_ports
    
    elif port_option == "Port Range":
        col1, col2 = st.columns(2)
        start_port = col1.number_input("Start Port", 1, 65535, 1)
        end_port = col2.number_input("End Port", 1, 65535, 1000)
        
        if start_port > end_port:
            st.error("Start port must be less than or equal to end port")
            ports_to_scan = []
        else:
            ports_to_scan = list(range(start_port, end_port + 1))
            st.info(f"Port Range: {len(ports_to_scan)} ports")
    
    elif port_option == "Specific Ports":
        port_list = st.text_input("Enter Ports (comma separated)", "80, 443, 22, 3389")
        try:
            ports_to_scan = [int(port.strip()) for port in port_list.split(',') if port.strip()]
        except:
            st.error("Invalid port format. Please enter comma-separated numbers.")
            ports_to_scan = []

    scan_button = st.button("Start Scan")

st.markdown("---")
st.subheader("Scan Results")

if scan_button and target_ips and ports_to_scan:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    scan_results = {
        "timestamp": timestamp,
        "scan_type": scan_type,
        "targets": target_ips,
        "ports_scanned": ports_to_scan,
        "results": {}
    }
    
    progress_text = "Scanning in progress. Please wait..."
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    total_ips = len(target_ips)
    for i, ip in enumerate(target_ips):
        status_text.text(f"Scanning {ip} ({i+1}/{total_ips})")
        
        try:
            ipaddress.ip_address(ip)
            
            ip_progress = st.progress(0)
            open_ports = scan_ip(ip, ports_to_scan, ip_progress, timeout)
            
            scan_results["results"][ip] = open_ports
            
            progress_bar.progress((i + 1) / total_ips)
            
        except Exception as e:
            st.error(f"Error scanning {ip}: {e}")
    
    status_text.empty()
    
    st.session_state.scan_history.append(scan_results)
    
    st.success("Scan completed!")
    
    tab1, tab2 = st.tabs(["Table View", "Raw Data"])
    
    with tab1:
        table_data = []
        for ip, ports in scan_results["results"].items():
            if not ports:
                table_data.append({"IP Address": ip, "Port": "None", "Service": "N/A", "Status": "All Closed"})
            else:
                for port_info in ports:
                    table_data.append({
                        "IP Address": ip,
                        "Port": port_info["port"],
                        "Service": port_info["service"],
                        "Status": "Open"
                    })
        
        if table_data:
            st.dataframe(pd.DataFrame(table_data))
        else:
            st.error("No open ports found.")
    
    with tab2:
        st.json(scan_results)
  
else:
    st.warning("Please enter target IP addresses and select scan options.")

st.markdown("---")
st.subheader("Scan History")

if st.session_state.scan_history:
    for i, scan in enumerate(reversed(st.session_state.scan_history)):
        with st.expander(f"Scan {len(st.session_state.scan_history) - i}: {scan['timestamp']} - {scan['scan_type']}"):
            st.write(f"Targets: {', '.join(scan['targets'][:5])}{'...' if len(scan['targets']) > 5 else ''}")
            st.write(f"Ports: {len(scan['ports_scanned'])} ports scanned")
            
            open_port_count = sum(len(ports) for ports in scan['results'].values())
            st.write(f"Results: {open_port_count} open ports found")
            
            if st.button(f"View Details #{i}"):
                st.json(scan)
else:
    st.warning("No scan history available. Run a scan to see results here.")
