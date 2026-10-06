"""Bounded, non-exploit traffic generator for authorized private-network IDS tests."""
from __future__ import annotations
import argparse
import ipaddress
import json
import platform
import random
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from urllib import error, request

AUTHORIZED_FLAG = "--authorized-lab-use"
DIRECT_OPENER = request.build_opener(request.ProxyHandler({}))
COMMON_TEST_PORTS = (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5000, 5432, 6379, 8080, 8443)

@dataclass
class Results:
    run_id: str
    target: str
    mode: str
    http_success: int = 0
    http_failed: int = 0
    tcp_open: int = 0
    tcp_closed_or_filtered: int = 0
    pings_sent: int = 0
    alerts_emitted: int = 0
    elapsed_seconds: float = 0.0

def is_allowed_lab_address(address: str) -> bool:
    """Allow only loopback, link-local, RFC1918 IPv4, or unique-local IPv6."""
    value = ipaddress.ip_address(address)
    if value.is_loopback or value.is_link_local:
        return True
    if isinstance(value, ipaddress.IPv4Address):
        return any(value in network for network in (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ))
    return value in ipaddress.ip_network("fc00::/7")

def resolve_private_target(target: str) -> tuple[str, ...]:
    try:
        records = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Target could not be resolved: {target}") from exc
    addresses = tuple(sorted({record[4][0] for record in records}))
    if not addresses:
        raise ValueError("Target resolved to no addresses")
    rejected = [address for address in addresses if not is_allowed_lab_address(address)]
    if rejected:
        raise ValueError("Public or non-lab targets are refused. Rejected address(es): " + ", ".join(rejected))
    return addresses

def host_for_url(address: str) -> str:
    return f"[{address}]" if ":" in address else address

def send_http_requests(address: str, port: int, count: int, delay_range: tuple[float, float], run_id: str, results: Results) -> None:
    base_url = f"http://{host_for_url(address)}:{port}"
    paths = ("/", "/health/live")
    for index in range(count):
        web_request = request.Request(
            base_url + paths[index % len(paths)],
            headers={"User-Agent": "NetMask-Authorized-Lab/1.0", "X-NetMask-Lab-Run": run_id, "Cache-Control": "no-cache"},
        )
        try:
            with DIRECT_OPENER.open(web_request, timeout=2) as response:
                response.read(128)
                if 200 <= response.status < 500:
                    results.http_success += 1
                else:
                    results.http_failed += 1
        except (error.URLError, TimeoutError, ConnectionError, OSError):
            results.http_failed += 1
        time.sleep(random.uniform(*delay_range))

def send_tcp_connections(address: str, ports: tuple[int, ...] | list[int], repeats: int, delay: float, results: Results) -> None:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    for _ in range(repeats):
        for port in ports:
            connection = socket.socket(family, socket.SOCK_STREAM)
            connection.settimeout(0.35)
            try:
                connection.connect((address, port))
                results.tcp_open += 1
            except OSError:
                results.tcp_closed_or_filtered += 1
            finally:
                connection.close()
            time.sleep(delay)

def send_pings(address: str, count: int, results: Results) -> None:
    count_flag = "-n" if platform.system() == "Windows" else "-c"
    timeout_flag = ["-w", "500"] if platform.system() == "Windows" else ["-W", "1"]
    try:
        subprocess.run(
            ["ping", count_flag, str(count), *timeout_flag, address],
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=max(10, count * 2),
        )
        results.pings_sent = count
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def send_authorized_lab_alert(address: str, port: int, token: str, results: Results) -> None:
    """Request a labelled dashboard notification; this sends no attack payload."""
    url = f"http://{host_for_url(address)}:{port}/api/lab-alert"
    lab_request = request.Request(
        url,
        method="POST",
        headers={"X-NetMask-Lab-Token": token, "X-NetMask-Lab-Run": results.run_id},
    )
    try:
        with DIRECT_OPENER.open(lab_request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if response.status == 200 and payload.get("success"):
            results.alerts_emitted = 1
            print(f"Authorized lab alert accepted. Sensor recorded this tester as: {payload.get('source_ip')}")
            return
    except (error.URLError, TimeoutError, ConnectionError, OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"The sensor did not accept the authorized lab alert: {exc}") from exc
    raise RuntimeError("The sensor did not accept the authorized lab alert. Check the token and sensor configuration.")

def run_profile(args: argparse.Namespace, address: str, results: Results) -> None:
    if args.mode == "alert":
        send_authorized_lab_alert(address, args.port, args.lab_token, results)
    elif args.mode == "baseline":
        send_http_requests(address, args.port, 20, (0.15, 0.30), results.run_id, results)
        send_tcp_connections(address, list(COMMON_TEST_PORTS[:8]) + [args.port], 1, 0.08, results)
        send_pings(address, 4, results)
    elif args.mode == "burst":
        send_http_requests(address, args.port, 80, (0.03, 0.08), results.run_id, results)
        send_tcp_connections(address, list(COMMON_TEST_PORTS) + [args.port], 2, 0.03, results)
        send_pings(address, 8, results)
    elif args.mode == "discovery":
        rng = random.Random(results.run_id)
        ports = sorted(rng.sample(range(1, 1025), 64))
        if args.port not in ports:
            ports.append(args.port)
        send_tcp_connections(address, ports, 1, 0.04, results)
        send_http_requests(address, args.port, 24, (0.08, 0.16), results.run_id, results)
        send_pings(address, 6, results)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate bounded, non-exploit traffic against an authorized NetMask Sentinel host on a private network.")
    parser.add_argument("--target", required=True, help="Private IP or private hostname")
    parser.add_argument("--port", type=int, default=5000, help="NetMask web port")
    parser.add_argument("--mode", choices=("alert", "baseline", "burst", "discovery"), default="baseline")
    parser.add_argument("--lab-token", help="Token displayed by the NetMask sensor for an authorized alert test")
    parser.add_argument(AUTHORIZED_FLAG, action="store_true", dest="authorized_lab_use", help="Confirm you own or are authorized to test the target")
    return parser.parse_args()

def main() -> int:
    args = parse_args()
    if not args.authorized_lab_use:
        print(f"Refused: pass {AUTHORIZED_FLAG} only when you own or are authorized to test the target.", file=sys.stderr)
        return 2
    if not 1 <= args.port <= 65535:
        print("Refused: port must be between 1 and 65535.", file=sys.stderr)
        return 2
    if args.mode == "alert" and not args.lab_token:
        print("Refused: --lab-token is required for alert mode.", file=sys.stderr)
        return 2
    try:
        addresses = resolve_private_target(args.target)
    except ValueError as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 2
    address = addresses[0]
    results = Results(run_id=uuid.uuid4().hex[:12], target=f"{address}:{args.port}", mode=args.mode)
    print("NetMask Sentinel - Authorized Lab Traffic")
    print(f"Run ID: {results.run_id}\nTarget: {results.target}\nProfile: {results.mode}")
    print("Payloads: none; connections and normal HTTP requests only.\n")
    started = time.monotonic()
    try:
        run_profile(args, address, results)
    except KeyboardInterrupt:
        print("\nStopped by user.")
        return 130
    finally:
        results.elapsed_seconds = round(time.monotonic() - started, 3)
    print(json.dumps(asdict(results), indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
