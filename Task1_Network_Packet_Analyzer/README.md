# Task 1 – Network Packet Analyzer

Implements the brief requirements: capture packets, inspect protocol behavior, extract source/destination IP, protocol and packet data, and present results clearly using Scapy.

 --Install Npcap on windows to run the network analyzer-- 

## Run
```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
pip install -r ../requirements.txt
python packet_analyzer.py --count 25 --timeout 20
```

To select an interface:
```bash
python packet_analyzer.py --interface "Wi-Fi" --count 50
```

On Linux, packet capture may require elevated privileges. On Windows, install Npcap with WinPcap compatibility enabled.

## Output
A live terminal table is printed and a JSON report is written to `captures/packet_report.json`.
