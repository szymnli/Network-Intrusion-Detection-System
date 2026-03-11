# Network Intrusion Detection System (NIDS)

A Python-based network intrusion detection system that monitors live network traffic and alerts on suspicious activity in real time.

Built with [Scapy](https://scapy.net/), [Rich](https://github.com/Textualize/rich), and [Pandas](https://pandas.pydata.org/).

---

## Features

- **Port Scan Detection** — detects when a single IP probes many ports within a short time window
- **SYN Flood Detection** — detects high-volume SYN packets targeting a single port
- **ICMP Sweep Detection** — detects ping sweeps across multiple hosts
- **Suspicious DNS Detection** — flags DNS queries to known malicious domains using a live threat feed from [Abuse.ch URLhaus](https://urlhaus.abuse.ch/)
- **Packet Logging** — all captured traffic is saved to a CSV file on exit
- **Alert Summary** — a summary of all triggered alerts is displayed on shutdown

---

## Project Structure

```
NIDS/
├── main.py          # Entry point
├── sniffer.py       # Packet capture and callback logic
├── detectors.py     # Detection engine (port scan, SYN flood, ICMP sweep, DNS)
├── config.py        # Thresholds, constants, and interface settings
├── logger.py        # Shared state — packet log, alert tracker, trackers
├── feeds.py         # Threat intelligence feed fetching (Abuse.ch URLhaus)
├── ui.py            # Terminal output and alert formatting
├── requirements.txt
└── README.md
```

---

## Requirements

- Python 3.10+
- Linux (tested on Kali Linux)
- `libpcap` installed on the system:

```bash
sudo apt install libpcap-dev
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/szymnli/Network-Intrusion-Detection-System.git
cd Network-Intrusion-Detection-System

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

The sniffer requires root privileges to capture raw packets:

```bash
sudo venv/bin/python main.py
```

On startup the program will:
1. Fetch the latest malicious domain list from Abuse.ch
2. Begin capturing traffic on the configured interface
3. Print live packet info to the terminal
4. Alert in real time when an attack pattern is detected
5. On `Ctrl+C`, display an alert summary and save all captured packets to `capture.csv`

---

## Configuration

All tunable parameters are in `config.py`:

| Parameter | Default | Description |
|---|---|---|
| `IFACE` | `eth0` | Network interface to monitor |
| `TIME_WINDOW` | `10` | Seconds to look back for pattern detection |
| `PORT_SCAN_THRESHOLD` | `15` | Unique ports before port scan alert |
| `SYN_FLOOD_THRESHOLD` | `100` | SYN packets to one port before flood alert |
| `ICMP_SWEEP_THRESHOLD` | `20` | Unique hosts pinged before sweep alert |
| `ALERT_COOLDOWN` | `300` | Seconds before re-alerting on the same IP |

---

## Detection Logic

### Port Scan
Tracks the number of unique destination ports contacted by each source IP within `TIME_WINDOW` seconds. Triggers when the count exceeds `PORT_SCAN_THRESHOLD`. Only SYN packets are counted.

### SYN Flood
Tracks the number of SYN packets sent by a source IP to a single destination port within `TIME_WINDOW` seconds. Triggers when the count exceeds `SYN_FLOOD_THRESHOLD`.

### ICMP Sweep
Tracks the number of unique destination IPs that a source IP sends ICMP echo requests (type 8) to within `TIME_WINDOW` seconds. Triggers when the count exceeds `ICMP_SWEEP_THRESHOLD`.

### Suspicious DNS
On every DNS query (UDP port 53), the queried domain is extracted and checked against a blocklist fetched from Abuse.ch URLhaus at startup. Any match triggers an immediate alert.

---

## Testing

All testing should be done in an isolated lab environment. A safe setup is two virtual machines connected via a **Host-Only Network** in VirtualBox.

| Attack | Tool | Command |
|---|---|---|
| Port scan | nmap | `sudo nmap -sS <target-ip>` |
| SYN flood | hping3 | `sudo hping3 -S -p 80 --flood <target-ip>` |
| ICMP sweep | nmap | `sudo nmap -sn --send-ip <subnet>/24` |
| DNS test | browser | Visit any domain in the blocklist, or add a known domain temporarily to test |

> **Warning:** Only run these tools against machines you own. Never test on a real network without explicit permission.

---

## Output

Captured packets are saved to `capture.csv` on exit with the following fields:

`Protocol`, `Source IP`, `Source Port`, `Destination IP`, `Destination Port`, `Packet Length`, `TCP Flag`, `ICMP Type`, `Timestamp`

> `capture.csv` is excluded from version control via `.gitignore` as it may contain sensitive network data.
