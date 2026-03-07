# Network-Intrusion-Detection-System
## To do
1. Packet Capture & Parsing
- Use Scapy to capture live traffic on a network interface ✅
- Parse and display key fields: source/dest IP, port, protocol, flags ✅
- Log all traffic to a .pcap or .csv file ✅
2. Detection Rules Engine
- Write a rule system (similar to Snort rules) in Python
- Detect: port scans (many ports hit in short time), SYN flood, ICMP ping sweeps, suspicious payloads
- Test against traffic you generate yourself using nmap on a local VM
3. Alerting & Visualization
- Generate real-time terminal alerts when rules trigger
- Build a simple dashboard using matplotlib or rich showing traffic stats
- Optionally: send email/webhook alerts using smtplib or a Discord bot
4. Testing, Docs & Presentation
- Set up a small lab (two VMs talking to each other) and simulate attacks
- Document your rules, architecture, and findings in a README
- Record a demo video showing a detection in action

## Tools & Libraries
- Scapy — packet capture and manipulation
- Pandas — traffic logging and analysis
- Rich — nice terminal output
- Matplotlib — basic visualization
- nmap / hping3 — to simulate attacks in your test lab
- VirtualBox or VMware — for a safe isolated lab

