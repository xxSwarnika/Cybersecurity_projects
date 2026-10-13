#!/usr/bin/env python3
"""Simple multi-threaded TCP port scanner (standard library only).

Only scan your own computers and networks, or systems you have clear
permission to test. Scanning other people's systems can be illegal and is
often against the rules of the network you are on.

Examples:
    python port_scanner.py 127.0.0.1                    # common ports
    python port_scanner.py 192.168.1.10 -p 1-1024       # a range
    python port_scanner.py localhost -p 22,80,443,8080  # specific ports
    python port_scanner.py localhost -p all --threads 500 --timeout 0.5
    python port_scanner.py localhost --banner           # also read service banners
"""

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 111, 123, 135, 137, 139, 143, 161, 389,
    443, 445, 465, 514, 587, 631, 993, 995, 1080, 1433, 1521, 2049, 2375, 3000, 3306,
    3389, 5000, 5432, 5672, 5900, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 11211, 27017,
]


def parse_ports(spec: str) -> list[int]:
    """Turn '22,80,100-200', 'common' or 'all' into a sorted list of ports."""
    spec = spec.strip().lower()
    if spec == "common":
        return sorted(COMMON_PORTS)
    if spec == "all":
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo, hi = (int(x) for x in part.split("-", 1))
                if lo > hi:
                    lo, hi = hi, lo
                ports.update(range(lo, hi + 1))
            else:
                ports.add(int(part))
        except ValueError:
            raise ValueError(f"'{part}' is not a valid port or range.")
    if not ports:
        raise ValueError("No ports given.")
    if min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports must be between 1 and 65535.")
    return sorted(ports)


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def grab_banner(ip: str, port: int, timeout: float) -> str:
    """Read whatever the service says first (SSH, FTP, SMTP do this).

    If it stays silent, send a tiny HTTP HEAD request in case it is a web server.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(min(timeout, 0.5))
            try:
                data = s.recv(256)
            except socket.timeout:
                data = b""
            if not data:
                s.settimeout(timeout)
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    data = s.recv(256)
                except OSError:
                    data = b""
        text = data.decode("utf-8", errors="replace").strip().splitlines()
        return text[0][:80] if text else ""
    except OSError:
        return ""


def scan_port(ip: str, port: int, timeout: float) -> tuple[int, str]:
    """Return (port, state) where state is 'open', 'closed' or 'filtered'."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        code = s.connect_ex((ip, port))
        if code == 0:
            return port, "open"
        # Connection refused means a host answered and nothing listens there.
        return port, "closed" if code in (111, 61, 10061) else "filtered"
    except socket.timeout:
        return port, "filtered"
    except OSError:
        return port, "filtered"
    finally:
        s.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple TCP port scanner.")
    parser.add_argument("target", help="hostname or IPv4 address to scan")
    parser.add_argument("-p", "--ports", default="common",
                        help="'common' (default), 'all', or a list like 22,80,100-200")
    parser.add_argument("-t", "--threads", type=int, default=200, help="parallel connections (default 200)")
    parser.add_argument("--timeout", type=float, default=1.0, help="seconds to wait per port (default 1.0)")
    parser.add_argument("-b", "--banner", action="store_true", help="try to read a banner from open ports")
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        sys.exit(f"Error: {e}")
    if not 1 <= args.threads <= 1000:
        sys.exit("Error: --threads must be between 1 and 1000.")

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        sys.exit(f"Error: could not resolve '{args.target}'.")

    print(f"Scanning {args.target} ({ip}) - {len(ports)} port{'s' if len(ports) != 1 else ''}, "
          f"{args.threads} threads, {args.timeout}s timeout")
    start = time.time()
    open_ports: list[int] = []
    counts = {"closed": 0, "filtered": 0}

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = [pool.submit(scan_port, ip, p, args.timeout) for p in ports]
            for fut in as_completed(futures):
                port, state = fut.result()
                if state == "open":
                    open_ports.append(port)
                else:
                    counts[state] += 1
    except KeyboardInterrupt:
        print("\nStopped early.")

    elapsed = time.time() - start
    open_ports.sort()
    print()
    if open_ports:
        print(f"{'PORT':<11}{'STATE':<7}{'SERVICE':<14}{'BANNER' if args.banner else ''}")
        for port in open_ports:
            banner = grab_banner(ip, port, args.timeout) if args.banner else ""
            print(f"{str(port) + '/tcp':<11}{'open':<7}{service_name(port):<14}{banner}")
    else:
        print("No open ports found.")
    print(f"\n{len(open_ports)} open, {counts['closed']} closed, {counts['filtered']} filtered "
          f"(no reply) in {elapsed:.2f}s")


if __name__ == "__main__":
    main()