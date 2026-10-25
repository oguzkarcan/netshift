"""Live traffic and DNS observation for the interface.

Only useful while traffic actually passes this machine (``mitm`` mode): on a
switched LAN, frames between two other hosts never reach our NIC. In ``block``
mode the counters stay quiet, which is itself a useful signal.

Nothing is stored on disk: the ring buffers live only while the interface is
open.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from scapy.all import DNS, AsyncSniffer, IP, IPv6, UDP

BUCKET = 0.5          # seconds per sparkline sample
WINDOW = 40           # samples kept per address (20 s)
QUERY_LIMIT = 200


class Monitor:
    def __init__(self, iface: str) -> None:
        self.iface = iface
        self.error = ""
        self._sniffer: AsyncSniffer | None = None
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}
        self._history: dict[str, deque[int]] = {}
        self._queries: deque[tuple[float, str, str]] = deque(maxlen=QUERY_LIMIT)
        self._bucket = time.time()

    @property
    def active(self) -> bool:
        return self._sniffer is not None

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> bool:
        for kwargs in ({"filter": "ip or ip6"}, {}):
            try:
                self._sniffer = AsyncSniffer(
                    iface=self.iface, prn=self._on_packet, store=0, **kwargs
                )
                self._sniffer.start()
                return True
            except Exception as exc:
                self.error = str(exc)
                self._sniffer = None
        return False

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

    # -- packet handling ---------------------------------------------------
    def _on_packet(self, packet) -> None:
        try:
            address = None
            if IP in packet:
                address = packet[IP]
            elif IPv6 in packet:
                address = packet[IPv6]
            if address is None:
                return

            size = len(packet)
            with self._lock:
                for host in (address.src, address.dst):
                    self._counts[host] = self._counts.get(host, 0) + size

            if UDP in packet and 53 in (packet[UDP].sport, packet[UDP].dport):
                self._observe_dns(packet)
        except Exception:
            pass

    def _observe_dns(self, packet) -> None:
        try:
            if DNS not in packet:
                return
            dns = packet[DNS]
            if dns.qr != 0:
                return
            questions = dns.qd
            if isinstance(questions, list):
                if not questions:
                    return
                question = questions[0]
            else:
                question = questions
            if question is None:
                return
            name = question.qname.decode("utf-8", "replace").rstrip(".")
            if not name:
                return
            with self._lock:
                self._queries.append((time.time(), packet[IP].src, name))
        except Exception:
            pass

    # -- sampling ----------------------------------------------------------
    def tick(self) -> None:
        """Fold the current bucket into history; call often from the UI loop."""
        now = time.time()
        with self._lock:
            if now - self._bucket < BUCKET:
                return
            for host, count in self._counts.items():
                history = self._history.setdefault(host, deque([0] * WINDOW, maxlen=WINDOW))
                history.append(count)
            self._counts.clear()
            self._bucket = now

    def series(self, ip: str, width: int = 20) -> list[int]:
        with self._lock:
            values = list(self._history.get(ip, ()))
        if len(values) < width:
            values = [0] * (width - len(values)) + values
        return values[-width:]

    def rate(self, ip: str) -> float:
        """Bytes per second over the most recent bucket."""
        with self._lock:
            history = self._history.get(ip)
            last = history[-1] if history else 0
        return last / BUCKET

    def recent(self, limit: int = 12) -> list[tuple[float, str, str]]:
        with self._lock:
            entries = list(self._queries)
        return entries[-limit:][::-1]

    def query_count(self, ip: str) -> int:
        with self._lock:
            return sum(1 for _, src, _ in self._queries if src == ip)

    def clear(self) -> None:
        with self._lock:
            self._queries.clear()
            self._history.clear()
            self._counts.clear()


def human_rate(bytes_per_second: float) -> str:
    if bytes_per_second < 1024:
        return f"{bytes_per_second:.0f} B/s"
    if bytes_per_second < 1024 * 1024:
        return f"{bytes_per_second / 1024:.1f} KB/s"
    return f"{bytes_per_second / (1024 * 1024):.1f} MB/s"
