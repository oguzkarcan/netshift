"""ARP discovery of the devices sharing the local subnet."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass

from scapy.all import ARP, Ether, srp

from . import oui


@dataclass
class Device:
    ip: str
    mac: str
    vendor: str = ""
    hostname: str = ""
    is_gateway: bool = False
    is_self: bool = False


def arp_scan(cidr: str, iface: str, timeout: float = 3.0) -> list[Device]:
    """Send ARP requests for *cidr* and collect the replies."""
    probe = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    answered, _ = srp(probe, iface=iface, timeout=timeout, retry=1, verbose=0)

    seen: dict[str, str] = {}
    for _sent, recv in answered:
        seen[recv.psrc] = recv.hwsrc.lower()

    devices = [Device(ip=ip, mac=mac, vendor=oui.vendor(mac)) for ip, mac in seen.items()]
    devices.sort(key=lambda d: tuple(int(part) for part in d.ip.split(".")))
    return devices


def _reverse_lookup(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def add_hostnames(devices: list[Device], timeout: float = 2.0) -> None:
    """Fill in hostnames with a bounded wait so scanning stays snappy."""
    if not devices:
        return
    with ThreadPoolExecutor(max_workers=min(32, len(devices))) as pool:
        futures = {pool.submit(_reverse_lookup, d.ip): d for d in devices}
        done, _ = wait(futures, timeout=timeout)
        for future in done:
            futures[future].hostname = future.result() or ""


def annotate(devices: list[Device], gateway: str, my_ip: str) -> None:
    for dev in devices:
        dev.is_gateway = dev.ip == gateway
        dev.is_self = dev.ip == my_ip
