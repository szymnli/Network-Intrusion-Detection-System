from rich import print
from rich.console import Console
from rich.table import Table
from scapy.all import *
import pandas as pd

IFACE = "wlp0s20f3"

packet_log = []
df = pd.DataFrame(
    columns=[
        "Protocol",
        "Source IP",
        "Source Port",
        "Destination IP",
        "Destination Port",
        "Packet length",
        "TCP Flag",
        "ICMP Type",
    ]
)


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
        icmp_type = None
        flag = packet[TCP].flags
    elif packet.haslayer(UDP):
        proto = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        icmp_type = None
        flag = None

    elif packet.haslayer(ICMP):
        proto = "ICMP"
        sport = None
        dport = None
        icmp_type = packet[ICMP].type
        flag = None

    else:
        return

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
    print(
        f"[{proto}] {src}:{sport} -> {dst}:{dport} ({len(packet)}) -- {flag} -- {icmp_type}"
    )


def save_log():
    df = pd.DataFrame(packet_log)
    df.to_csv("capture.csv", index=False)


def main():
    sniff(
        filter="tcp or udp or icmp",
        iface=IFACE,
        prn=packet_callback,
    )
    print("\nStopping sniffer...")
    save_log()
    print(f"Saved {len(packet_log)} packets to capture.csv")



if __name__ == "__main__":
    main()
