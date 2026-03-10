# Name of the capturing network interface
IFACE = "eth0"
# Time window for detecting port scans
TIME_WINDOW = 10
# Amount of unique ports a single IP address needs to scan to trigger port scan detection
PORT_SCAN_THRESHOLD = 15
# Amount of SYN TCP packets sent to a single port needed to trigger detection
SYN_FLOOD_THRESHOLD = 100
# Amount of destination IP addresses a device can send ICMP echo request to, to trigger detection
ICMP_SWEEP_THRESHOLD = 20
# Amount of time for generating another alert for the same IP addr
ALERT_COOLDOWN = 300
# Set for containing fetched malicious DNS hostnames from urlhaus.abuse.ch
MALICIOUS_DOMAINS = set()
