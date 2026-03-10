from rich.console import Console

console = Console()


def show_packet(proto, src, sport, dst, dport, length, flag, icmp_type):
    console.print(
        f"[dim][{proto}] {src}:{sport} -> {dst}:{dport} ({length}) -- {flag} -- {icmp_type}[/dim]"
    )


def show_alert(attack_type, src, detail):
    console.rule(style="red")
    console.print(
        f"  [bold red][!] {attack_type} DETECTED[/bold red] -- [yellow]{src}[/yellow] | {detail}"
    )
    console.rule(style="red")


def show_summary(alerted_ips):
    # Displaying alert summary
    num_alerts = len(alerted_ips)
    if num_alerts > 0:
        console.print(f"\n[!] {num_alerts} alert(s) detected:")
        for ip, info in alerted_ips.items():
            console.print(f"> {ip[0]} - {info['type']}")


def show_shutdown(packet_count):
    console.print("\nStopping sniffer...")
    console.print(f"Saved {packet_count} packets to capture.csv")
