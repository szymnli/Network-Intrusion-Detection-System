from rich import print
from rich.console import Console
from rich.table import Table
from scapy.all import *
import pandas as pd
from collections import defaultdict
import time

# Name of the capturing network interface
IFACE = "wlp0s20f3"

# Time window for detecting port scans
TIME_WINDOW = 10

# Amount of unique ports a single IP address needs to scan
# to trigger port scan detection
PORT_SCAN_THRESHOLD = 15

# Amount of time for generating another alert for the same IP addr
ALERT_COOLDOWN = 300

# List for containing sniffer logs
packet_log = []
# Dict for containing ports each IP addr has scanned with a timestamp
port_scan_tracker = defaultdict(dict)
# Dict for containing IP addresses that triggered an alert
alerted_ips = {}


def packet_callback(packet):
    # Detect:
    # port scan
    # SYN flood
    # ICMP sweep
    # Suspicious DNS

    # Checking if a packet has an IP layer
    if not packet.haslayer(IP):
        return

    # Saving source and destination IP addresses from a packet
    src = packet[IP].src
    dst = packet[IP].dst

    # TCP specific variables
    if packet.haslayer(TCP):
        proto = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        icmp_type = None
        flag = packet[TCP].flags
    # UDP specific variables
    elif packet.haslayer(UDP):
        proto = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        icmp_type = None
        flag = None
    # ICMP specific variables
    elif packet.haslayer(ICMP):
        proto = "ICMP"
        sport = None
        dport = None
        icmp_type = packet[ICMP].type
        flag = None

    else:
        return

    # Only include TCP SYN packets for port scan checking
    if proto == "TCP" and str(flag) == "S":
        detect_port_scan(src, dport)

    # Adding packet information to the log list
    packet_log.append(
        {
            "Protocol": proto,
            "Source IP": src,
            "Source Port": sport,
            "Destination IP": dst,
            "Destination Port": dport,
            "Packet Length": len(packet),
            "TCP Flag": flag,
            "ICMP Type": icmp_type,
        }
    )

    # Displaying all captured traffic
    # print(
        #f"[{proto}] {src}:{sport} -> {dst}:{dport} ({len(packet)}) -- {flag} -- {icmp_type}"
    #)


def detect_port_scan(src, dport):
    # Get current time
    now = time.time()
    # Add timestamp to an entry {src : {dport : timestamp}}
    port_scan_tracker[src][dport] = now
    # Creating a dict for entries only from the TIME_WINDOW
    recent_ports = {
        port: t for port, t in port_scan_tracker[src].items() if now - t < TIME_WINDOW
    }
    # Removing entries older than TIME_WINDOW
    port_scan_tracker[src] = recent_ports

    # Checking if a single IP addr sent packet to more ports than PORT_SCAN_THRESHOLD
    # and if an alert hasn't already been issued within the ALERT_COOLDOWN 
    if len(recent_ports) > PORT_SCAN_THRESHOLD and (src not in alerted_ips or now - alerted_ips[src] > ALERT_COOLDOWN):
        alerted_ips[src] = now
        print(
            f"[!] PORT SCAN DETECTED — {src} has hit {len(port_scan_tracker[src])} unique ports within {TIME_WINDOW} seconds"
        )


def save_log():
    # Creating a pandas dataframe out of the generated logs
    # and saving it to a csv file
    df = pd.DataFrame(packet_log)
    df.to_csv("capture.csv", index=False)


def main():
    # Starting the sniffing process
    sniff(
        filter="tcp or udp or icmp",
        iface=IFACE,
        prn=packet_callback,
    )

    # Displaying alert summary
    if len(alerted_ips) > 0:
        for ip in alerted_ips:
            print(f"\n[!] {ip} caused an alert")

    # Saving logs to a file
    print("\nStopping sniffer...")
    save_log()
    print(f"Saved {len(packet_log)} packets to capture.csv")


if __name__ == "__main__":
    main()
