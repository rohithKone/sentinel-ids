from __future__ import annotations

import argparse
import json
import sys
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    from scapy.all import IP, TCP, sniff
except ImportError:  # Allow config/help and offline rule development without Scapy.
    IP = TCP = None
    sniff = None


@dataclass
class Alert:
    timestamp: str
    kind: str
    source: str
    detail: str
    severity: str = "medium"


class Detector:
    """Stateful, heuristic detector for common noisy network behavior."""

    def __init__(self, window_seconds: int = 10, port_scan_threshold: int = 12,
                 syn_threshold: int = 40, watched_ports: set[int] | None = None):
        self.window = window_seconds
        self.port_scan_threshold = port_scan_threshold
        self.syn_threshold = syn_threshold
        self.watched_ports = watched_ports or {21, 23, 445, 3389, 4444}
        self.dest_ports: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self.syn_counts: dict[str, deque[float]] = defaultdict(deque)
        self.alerted: dict[tuple[str, str], float] = {}

    def _trim(self, q: deque, now: float) -> None:
        while q:
            oldest = q[0][0] if isinstance(q[0], tuple) else q[0]
            if now - oldest <= self.window:
                break
            q.popleft()

    def inspect(self, source: str, destination: str, protocol: str,
                destination_port: int | None, syn: bool = False,
                now: float | None = None) -> list[Alert]:
        now = time.monotonic() if now is None else now
        alerts: list[Alert] = []
        if protocol.lower() == "tcp" and destination_port is not None:
            ports = self.dest_ports[source]
            ports.append((now, destination_port))
            self._trim(ports, now)
            unique = {port for _, port in ports}
            if len(unique) >= self.port_scan_threshold:
                alert = self._once(source, "port_scan", now,
                                   f"Contacted {len(unique)} destination ports within {self.window}s", "high")
                if alert: alerts.append(alert)
            if destination_port in self.watched_ports:
                alert = self._once(source, f"watched_{destination_port}", now,
                                   f"TCP connection to watched port {destination_port}")
                if alert: alerts.append(alert)
            if syn:
                syns = self.syn_counts[source]
                syns.append(now)
                self._trim(syns, now)
                if len(syns) >= self.syn_threshold:
                    alert = self._once(source, "syn_burst", now,
                                       f"Observed {len(syns)} TCP SYN packets within {self.window}s", "high")
                    if alert: alerts.append(alert)
        return alerts

    def _once(self, source: str, kind: str, now: float, detail: str, severity: str = "medium") -> Alert | None:
        key = (source, kind)
        if now - self.alerted.get(key, -1e9) < self.window:
            return None
        self.alerted[key] = now
        return Alert(datetime.now(timezone.utc).isoformat(), kind, source, detail, severity)


def packet_fields(packet: Any) -> tuple[str, str, str, int | None, bool] | None:
    if IP is None or not packet.haslayer(IP):
        return None
    ip = packet[IP]
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        return ip.src, ip.dst, "tcp", int(tcp.dport), bool(int(tcp.flags) & 0x02)
    return ip.src, ip.dst, str(ip.proto), None, False


class AlertFeed:
    def __init__(self, output: Path | None):
        self.output = output
        self.items: deque[dict[str, str]] = deque(maxlen=500)
        self.lock = threading.Lock()
        self.started = datetime.now(timezone.utc).isoformat()
        self.packet_count = 0

    def packet_seen(self) -> None:
        with self.lock:
            self.packet_count += 1

    def add(self, alert: Alert) -> None:
        record = asdict(alert)
        line = json.dumps(record, ensure_ascii=False)
        print(line, flush=True)
        with self.lock:
            self.items.appendleft(record)
        if self.output:
            self.output.parent.mkdir(parents=True, exist_ok=True)
            with self.output.open("a", encoding="utf-8") as f:
                f.write(line + "\n")


def start_dashboard(feed: AlertFeed, port: int) -> ThreadingHTTPServer:
    dashboard_root = Path(__file__).resolve().parent.parent / "web"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/api/alerts":
                with feed.lock:
                    payload = list(feed.items)
            elif path == "/api/status":
                with feed.lock:
                    payload = {"status": "monitoring", "started": feed.started,
                               "packets_seen": feed.packet_count, "alerts": len(feed.items)}
            elif path in ("/", "/index.html", "/app.js", "/styles.css"):
                name = "index.html" if path == "/" else path.lstrip("/")
                file_path = dashboard_root / name
                if not file_path.is_file():
                    self.send_error(404)
                    return
                content_type = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                                ".css": "text/css; charset=utf-8"}.get(file_path.suffix, "application/octet-stream")
                data = file_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)
                return
            else:
                self.send_error(404)
                return
            data = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description="Passive heuristic IDS for a trusted network interface.")
    parser.add_argument("--interface", help="Interface to monitor (requires packet-capture privileges)")
    parser.add_argument("--filter", default="ip", help='BPF capture filter, e.g. "tcp" or "tcp and port 443"')
    parser.add_argument("--output", type=Path, default=Path("alerts.jsonl"), help="JSONL alert file; use --no-file to disable")
    parser.add_argument("--no-file", action="store_true", help="Print alerts without writing a file")
    parser.add_argument("--window", type=int, default=10)
    parser.add_argument("--port-scan-threshold", type=int, default=12)
    parser.add_argument("--syn-threshold", type=int, default=40)
    parser.add_argument("--dashboard", action="store_true", help="Serve the local web dashboard alongside capture")
    parser.add_argument("--dashboard-port", type=int, default=8765)
    args = parser.parse_args()
    if args.window < 1 or args.port_scan_threshold < 2 or args.syn_threshold < 2:
        parser.error("thresholds must be positive; port scan and SYN thresholds must be at least 2")
    if sniff is None:
        print("Scapy is required. Install dependencies with: python -m pip install -r requirements.txt", file=sys.stderr)
        return 2

    output = None if args.no_file else args.output
    feed = AlertFeed(output)
    if args.dashboard:
        try:
            start_dashboard(feed, args.dashboard_port)
        except OSError as exc:
            print(f"Dashboard could not start: {exc}", file=sys.stderr)
            return 1
        print(f"Dashboard: http://127.0.0.1:{args.dashboard_port}", flush=True)
    detector = Detector(args.window, args.port_scan_threshold, args.syn_threshold)
    print(f"Watching {args.interface or 'default interface'}; filter={args.filter!r}. Ctrl+C to stop.", flush=True)

    def handle(packet: Any) -> None:
        feed.packet_seen()
        fields = packet_fields(packet)
        if fields is None: return
        for alert in detector.inspect(*fields):
            feed.add(alert)

    try:
        sniff(iface=args.interface, filter=args.filter, prn=handle, store=False)
    except KeyboardInterrupt:
        print("Capture stopped.", flush=True)
    except PermissionError:
        print("Packet capture requires elevated privileges on this system.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Capture could not start: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

