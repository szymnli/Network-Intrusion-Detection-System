import time

from scapy.all import *  # type: ignore

from config import (
    ALERT_COOLDOWN,
    ICMP_SWEEP_THRESHOLD,
    MALICIOUS_DOMAINS,
    PORT_SCAN_THRESHOLD,
    SYN_FLOOD_THRESHOLD,
    TIME_WINDOW,
)
from logger import (
    alerted_ips,
    icmp_sweep_tracker,
    port_scan_tracker,
    syn_flood_tracker,
)
from ui import show_alert


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
        show_alert(
            "PORT SCAN", src, f"{len(recent_ports)} unique ports within {TIME_WINDOW}s"
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
        show_alert(
            "SYN FLOOD",
            src,
            f"{len(recent)} SYN packets to port {dport} within {TIME_WINDOW}s",
        )


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
        show_alert(
            "ICMP SWEEP",
            src,
            f"ICMP echo requests to {len(recent_dst_ips)} IPs within {TIME_WINDOW}s",
        )


def detect_suspicious_dns(src, packet):
    # Check if the packet contains a DNS query record
    if not packet.haslayer(DNSQR):
        return

    now = time.time()
    # Extract the DNS domain name
    dns = packet[DNSQR].qname.decode().strip(".")
    key = (src, "SUSPICIOUS DNS")

    # Check if the DNS domain is malicious and alert if not seen recently
    if dns in MALICIOUS_DOMAINS and (
        key not in alerted_ips or now - alerted_ips[key]["time"] > ALERT_COOLDOWN
    ):
        alerted_ips[key] = {"time": now, "type": "SUSPICIOUS DNS"}
        show_alert("SUSPICIOUS DNS", src, f"Queried malicious domain: {dns}")
