import argparse
import random
import socket
import subprocess
import sys
import time
from urllib import error, request

from netmask_lab_traffic import resolve_private_target


def http_burst(base_url: str, count: int, min_delay: float, max_delay: float) -> None:
    print(f"[http] Sending {count} requests to {base_url}")
    ok = 0
    fail = 0
    for i in range(count):
        try:
            with request.urlopen(base_url, timeout=3) as resp:
                _ = resp.read(64)
                if 200 <= resp.status < 400:
                    ok += 1
                else:
                    fail += 1
        except (error.URLError, TimeoutError, ConnectionError):
            fail += 1
        if min_delay > 0 or max_delay > 0:
            time.sleep(random.uniform(min_delay, max_delay))
        if (i + 1) % 25 == 0:
            print(f"[http] Progress: {i + 1}/{count}")
    print(f"[http] Done. Success={ok}, Failed={fail}")


def tcp_connect_attempts(host: str, ports: list[int], repeats: int, timeout: float) -> None:
    total = len(ports) * repeats
    print(f"[tcp] Attempting {total} TCP connections to {host}")
    attempts = 0
    for _ in range(repeats):
        for port in ports:
            attempts += 1
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.connect((host, port))
            except OSError:
                pass
            finally:
                sock.close()
            if attempts % 50 == 0:
                print(f"[tcp] Progress: {attempts}/{total}")
    print(f"[tcp] Done. Attempts={attempts}")


def ping_burst(host: str, count: int) -> None:
    print(f"[icmp] Sending {count} pings to {host}")
    cmd = ["ping", host, "-n", str(count)]
    try:
        subprocess.run(cmd, check=False)
    except FileNotFoundError:
        print("[icmp] ping command not found on this system")


def trigger_mock_flows(base_url: str, count: int, delay: float) -> None:
    url = base_url.rstrip("/") + "/debug/mock-flow"
    print(f"[mock] Triggering {count} mock flow events via {url}")
    ok = 0
    fail = 0
    for i in range(count):
        req = request.Request(url, method="POST")
        try:
            with request.urlopen(req, timeout=3) as resp:
                if 200 <= resp.status < 400:
                    ok += 1
                else:
                    fail += 1
        except (error.URLError, TimeoutError, ConnectionError):
            fail += 1
        if delay > 0:
            time.sleep(delay)
        if (i + 1) % 10 == 0:
            print(f"[mock] Progress: {i + 1}/{count}")
    print(f"[mock] Done. Success={ok}, Failed={fail}")


def run_mode(mode: str, host: str, port: int) -> None:
    base_url = f"http://{host}:{port}/"
    if mode == "normal":
        http_burst(base_url, count=40, min_delay=0.15, max_delay=0.45)
        tcp_connect_attempts(host, ports=[22, 80, 443, 3389], repeats=6, timeout=0.35)
        ping_burst(host, count=40)
    elif mode == "stress":
        http_burst(base_url, count=300, min_delay=0.01, max_delay=0.05)
        tcp_connect_attempts(host, ports=[1, 22, 53, 80, 135, 139, 443, 445, 3389, 8080], repeats=30, timeout=0.2)
        ping_burst(host, count=200)
    elif mode == "scan-like":
        # Safe scan-like pattern: lots of connection attempts only.
        ports = list(range(1, 1025))
        random.shuffle(ports)
        tcp_connect_attempts(host, ports=ports[:300], repeats=2, timeout=0.18)
        http_burst(base_url, count=120, min_delay=0.0, max_delay=0.03)
    elif mode == "mock":
        # Best for demos when local packet capture is unavailable on Windows.
        trigger_mock_flows(base_url, count=50, delay=0.08)
    else:
        raise ValueError(f"Unsupported mode: {mode}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Safe network traffic generator for NetMask Sentinel validation (non-destructive)."
    )
    parser.add_argument(
        "--mode",
        choices=["normal", "stress", "scan-like", "mock"],
        default="stress",
        help="Traffic profile to generate.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Target host/IP.")
    parser.add_argument("--port", type=int, default=5000, help="Target HTTP port.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        args.host = resolve_private_target(args.host)[0]
    except ValueError as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 2
    print("=== NetMask Sentinel Safe Traffic Test ===")
    print(f"Mode: {args.mode}")
    print(f"Target: {args.host}:{args.port}")
    print("This generates test traffic only. No exploit payloads are used.\n")
    start = time.time()
    run_mode(args.mode, args.host, args.port)
    elapsed = time.time() - start
    print(f"\nCompleted in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
