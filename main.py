from scapy.all import *


def packet_callback(packet):
    print(packet.show())


def main():
    sniff(
        filter="tcp or udp or icmp",
        iface="wlp0s20f3",
        prn=packet_callback,
    )


if __name__ == "__main__":
    main()
