from rich import print
from rich.console import Console
from rich.table import Table
from scapy.all import *

IFACE = "wlp0s20f3"


def packet_callback(packet):
    # Detect:
    # port scan
    # SYN flood
    # ICMP sweep
    # Suspicious DNS

    if not packet.haslayer(IP):
        return
    
    src = packet[IP].src
    dst = packet[IP].dst

    if packet.haslayer(TCP):
        proto = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
    elif packet.haslayer(UDP):
        proto = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport
    elif packet.haslayer(ICMP):
        proto = "ICMP"
        sport = None
        dport = None
    else:
        return
    
    print(f"[{proto}] {src}:{sport} -> {dst}:{dport}")


def main():
    sniff(
        filter="tcp or udp or icmp",
        iface=IFACE,
        prn=packet_callback,
    )


if __name__ == "__main__":
    main()
