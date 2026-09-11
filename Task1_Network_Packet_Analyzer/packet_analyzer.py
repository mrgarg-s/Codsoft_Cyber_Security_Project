#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, time
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw, sniff

PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}
def packet_to_record(pkt: Any, index: int) -> dict[str, Any]:
    src = dst = "-"
    protocol = "OTHER"
    sport = dport = None
    info = ""

    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
        protocol = PROTO_NAMES.get(int(pkt[IP].proto), str(pkt[IP].proto))
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
        protocol = PROTO_NAMES.get(int(pkt[IPv6].nh), str(pkt[IPv6].nh))
    elif ARP in pkt:
        src, dst, protocol = pkt[ARP].psrc, pkt[ARP].pdst, "ARP"

    if TCP in pkt:
        sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
        flags = str(pkt[TCP].flags)
        info = f"TCP {sport}->{dport} flags={flags}"
    elif UDP in pkt:
        sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
        info = f"UDP {sport}->{dport}"
    elif ICMP in pkt:
        info = f"ICMP type={int(pkt[ICMP].type)} code={int(pkt[ICMP].code)}"

    if DNS in pkt:
        protocol = "DNS"
        info = f"DNS id={int(pkt[DNS].id)}"

    raw_preview = ""
    if Raw in pkt:
        raw_preview = bytes(pkt[Raw].load)[:96].hex(" ")

    return {
        "index": index,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "length": len(pkt),
        "source_ip": src,
        "destination_ip": dst,
        "protocol": protocol,
        "source_port": sport,
        "destination_port": dport,
        "summary": info or pkt.summary(),
        "payload_hex_preview": raw_preview,
    }


def print_record(r: dict[str, Any]) -> None:
    print(f"{r['index']:>4} | {r['protocol']:<7} | {r['source_ip']:<39} -> {r['destination_ip']:<39} | {r['length']:>5} B")


def main() -> None:
    p = argparse.ArgumentParser(description="Authorized network packet analyzer")
    p.add_argument("--interface", "-i", help="Interface name; omit to use Scapy's default")
    p.add_argument("--count", "-c", type=int, default=20, help="Number of packets (0 = until timeout)")
    p.add_argument("--timeout", "-t", type=int, default=15, help="Capture timeout in seconds")
    p.add_argument("--filter", default="ip or ip6 or arp", help="BPF filter")
    args = p.parse_args()
    if args.count < 0 or args.timeout <= 0:
        p.error("count must be >= 0 and timeout must be > 0")

    records: list[dict[str, Any]] = []
    start = time.time()

    def handle(pkt: Any) -> None:
        record = packet_to_record(pkt, len(records) + 1)
        records.append(record)
        print_record(record)

    print("Authorized capture only. Press Ctrl+C to stop.")
    print(" IDX | PROTO   | SOURCE                                  -> DESTINATION                             |  LEN")
    print("-" * 120)
    try:
        sniff(iface=args.interface, filter=args.filter, prn=handle,
              count=args.count, timeout=args.timeout, store=False)
    except PermissionError:
        raise SystemExit("Permission denied. Run with appropriate capture permissions on your own system.")
    except Exception as exc:
        raise SystemExit(f"Capture failed: {exc}")

    os.makedirs("captures", exist_ok=True)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(time.time() - start, 2),
        "packet_count": len(records),
        "protocol_counts": dict(Counter(r["protocol"] for r in records)),
        "packets": records,
    }
    path = os.path.join("captures", "packet_report.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\nSaved report: {path}")


if __name__ == "__main__":
    main()
