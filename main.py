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

# Amount of SYN TCP packets sent to a single port needed to trigger detection
SYN_FLOOD_THRESHOLD = 100

# Amount of destination IP addresses a device can send ICMP echo request to, to trigger detection
ICMP_SWEEP_THRESHOLD = 20

# Amount of time for generating another alert for the same IP addr
ALERT_COOLDOWN = 300

# List for containing sniffer logs
packet_log = []
# Dict for containing ports each IP addr has scanned with a timestamp
port_scan_tracker = defaultdict(dict)
# Dict for containing number of packets sent to each port with a timestamp
syn_flood_tracker = defaultdict(list)
# Dict for containing amount of hosts a single IP address has pinged with a timestamp
icmp_sweep_tracker = defaultdict(dict)
# Dict for containing IP addresses that triggered an alert
alerted_ips = {}


def packet_callback(packet):
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

    # Only include TCP SYN packets for port scan and SYN flood checking
    if proto == "TCP" and str(flag) == "S":
        detect_port_scan(src, dport)
        detect_syn_flood(src, dport)
    # Only ICMP echo packets for ICMP sweep checking
    elif proto == "ICMP" and icmp_type == 8:
        detect_icmp_sweep(src, dst)

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
            "Timestamp": time.time(),
        }
    )

    # Displaying all captured traffic
    """
    print(
        f"[{proto}] {src}:{sport} -> {dst}:{dport} ({len(packet)}) -- {flag} -- {icmp_type}"
    )
    """


def detect_icmp_sweep(src, dst):
    # Get current time
    now = time.time()
    # Add timestamp to an entry {src: {dst: timestamp, ... }}
    icmp_sweep_tracker[src][dst] = now
    # Creating a dict for entries only from the TIME_WINDOW
    recent_dst_ips = {
        d: t for d, t in icmp_sweep_tracker[src].items() if now - t < TIME_WINDOW
    }
    # Removing entries older than TIME_WINDOW
    icmp_sweep_tracker[src] = recent_dst_ips
    # Alert if count exceeds threshold
    key = src, "ICMP SWEEP"
    if len(recent_dst_ips) > ICMP_SWEEP_THRESHOLD and (
        key not in alerted_ips or now - alerted_ips[key]["time"] > ALERT_COOLDOWN
    ):
        alerted_ips[key] = {"time": now, "type": "ICMP SWEEP"}
        print(
            f"[!] ICMP SWEEP DETECTED -- {src} sent ICMP echo requests to {len(recent_dst_ips)} IPs within {TIME_WINDOW} seconds"
        )


def detect_syn_flood(src, dport):
    # Get current time
    now = time.time()
    # Append timestamp of a packet to the tracker list
    key = src, dport
    syn_flood_tracker[key].append(now)
    # Keep entries only from the TIME_WINDOW
    recent = [t for t in syn_flood_tracker[key] if now - t < TIME_WINDOW]
    syn_flood_tracker[key] = recent

    # Alert if count exceeds threshold
    key = src, "SYN FLOOD"
    if len(recent) > SYN_FLOOD_THRESHOLD and (
        key not in alerted_ips or now - alerted_ips[key]["time"] > ALERT_COOLDOWN
    ):
        alerted_ips[key] = {"time": now, "type": "SYN FLOOD"}
        print(
            f"[!] SYN FLOOD DETECTED -- {src} sent {len(recent)} SYN packets to port {dport} within {TIME_WINDOW} seconds"
        )


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
    key = src, "PORT SCAN"
    if len(recent_ports) > PORT_SCAN_THRESHOLD and (
        key not in alerted_ips or now - alerted_ips[key]["time"] > ALERT_COOLDOWN
    ):
        alerted_ips[key] = {"time": now, "type": "PORT SCAN"}
        print(
            f"[!] PORT SCAN DETECTED -- {src} has hit {len(port_scan_tracker[src])} unique ports within {TIME_WINDOW} seconds"
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
    num_alerts = len(alerted_ips)
    if num_alerts > 0:
        print("\n\n")
        if num_alerts > 1:
            print(f"[!] {len(alerted_ips)} alerts detected")
        else:
            print(f"[!] alert detected:")
        for ip, info in alerted_ips.items():
            print(f"> {ip} - {info['type']}")

    # Saving logs to a file
    print("\nStopping sniffer...")
    save_log()
    print(f"Saved {len(packet_log)} packets to capture.csv")


if __name__ == "__main__":
    main()
