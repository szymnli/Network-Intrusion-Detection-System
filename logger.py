import time
from collections import defaultdict

import pandas as pd

# List for containing sniffer logs
packet_log = []
# Dict for containing IP addresses that triggered an alert
alerted_ips = {}
# Dict for containing ports each IP addr has scanned with a timestamp
port_scan_tracker = defaultdict(dict)
# Dict for containing number of packets sent to each port with a timestamp
syn_flood_tracker = defaultdict(list)
# Dict for containing amount of hosts a single IP address has pinged with a timestamp
icmp_sweep_tracker = defaultdict(dict)


def save_log():
    # Creating a pandas dataframe out of the generated logs and saving it to a csv file
    df = pd.DataFrame(packet_log)
    df.to_csv("capture.csv", index=False)


def log_packet(proto, src, sport, dst, dport, length, flag, icmp_type):
    # Adding packet information to the log list
    packet_log.append(
        {
            "Protocol": proto,
            "Source IP": src,
            "Source Port": sport,
            "Destination IP": dst,
            "Destination Port": dport,
            "Packet Length": length,
            "TCP Flag": flag,
            "ICMP Type": icmp_type,
            "Timestamp": time.time(),
        }
    )
