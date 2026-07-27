"""Replay a PCAP through the same flow and detection contracts used by NetMask Sentinel."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scapy.utils import PcapReader

from netmask.detection import DetectionEngine
from netmask.features import split_flow_record
from netmask.sensor import FlowTracker


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Replay an authorized PCAP through NetMask Sentinel")
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--model", type=Path, default=Path("models/model.pkl"))
    parser.add_argument("--output", type=Path, default=Path("reports/pcap-replay.jsonl"))
    parser.add_argument("--flow-timeout", type=int, default=120)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.pcap.is_file():
        print(f"PCAP not found: {args.pcap}", file=sys.stderr)
        return 2

    engine = DetectionEngine.from_pickle(args.model)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    detected = 0
    invalid = 0

    with args.output.open("w", encoding="utf-8") as destination:
        def on_flow(record: list[object]) -> None:
            nonlocal detected, invalid
            try:
                features, metadata = split_flow_record(record)
                result = engine.detect(features)
                payload = {"metadata": metadata, "detection": result.to_dict()}
                destination.write(json.dumps(payload, default=str) + "\n")
                detected += 1
            except Exception as exc:
                invalid += 1
                destination.write(json.dumps({"error": str(exc)}) + "\n")

        tracker = FlowTracker(on_flow, timeout_seconds=args.flow_timeout)
        packet_count = 0
        with PcapReader(str(args.pcap)) as packets:
            for packet in packets:
                packet_count += 1
                tracker.handle_packet(packet)
        tracker.flush()

    summary = {
        "packets": packet_count,
        "flows_detected": detected,
        "invalid_flows": invalid,
        "output": str(args.output.resolve()),
    }
    print(json.dumps(summary, indent=2))
    return 0 if detected else 1


if __name__ == "__main__":
    raise SystemExit(main())