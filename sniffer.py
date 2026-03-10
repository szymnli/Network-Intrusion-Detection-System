from scapy.all import *  # type: ignore

from config import IFACE, MALICIOUS_DOMAINS
from detectors import (
    detect_icmp_sweep,
    detect_port_scan,
    detect_suspicious_dns,
    detect_syn_flood,
)
from feeds import fetch_malicious_domains
from logger import alerted_ips, log_packet, packet_log, save_log
from ui import show_packet, show_shutdown, show_summary


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
    elif proto == "UDP" and dport == 53:
        detect_suspicious_dns(src, packet)

    # Adding packet information to the log list
    log_packet(proto, src, sport, dst, dport, len(packet), flag, icmp_type)

    # Displaying all captured traffic
    show_packet(proto, src, sport, dst, dport, len(packet), flag, icmp_type)


def start_sniffing():
    print("Fetching malicious domain feed...")
    MALICIOUS_DOMAINS.update(fetch_malicious_domains())
    print(f"Loaded {len(MALICIOUS_DOMAINS)} malicious domains")
    # Starting the sniffing process
    sniff(
        filter="tcp or udp or icmp",
        iface=IFACE,
        prn=packet_callback,
    )
    show_summary(alerted_ips)
    show_shutdown(len(packet_log))
    save_log()
