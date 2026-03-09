from config import TIME_WINDOW

def show_packet(proto, src, sport, dst, dport, length, flag, icmp_type):
    print(f"[{proto}] {src}:{sport} -> {dst}:{dport} ({length}) -- {flag} -- {icmp_type}")

def show_alert(attack_type, src, detail):
    print(f"[!] {attack_type} DETECTED -- {src} | {detail}")

def show_summary(alerted_ips):
    # Displaying alert summary
    num_alerts = len(alerted_ips)
    if num_alerts > 0:
        print("\n")
        print(f"[!] {num_alerts} alert(s) detected:")
        for ip, info in alerted_ips.items():
            print(f"> {ip} - {info['type']}")

def show_shutdown(packet_count):
    print("\nStopping sniffer...")
    print(f"Saved {packet_count} packets to capture.csv")