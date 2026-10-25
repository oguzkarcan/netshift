"""Interface, address and gateway discovery for Linux and macOS."""

from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
from dataclasses import dataclass

from scapy.all import conf, get_if_addr, get_if_hwaddr


@dataclass(frozen=True)
class NetInfo:
    iface: str
    ip: str
    mac: str
    gateway: str
    netmask: str
    cidr: str

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(self.cidr, strict=False)


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return ""


def netmask_for(iface: str) -> str:
    """Return the IPv4 netmask of *iface* as a dotted quad."""
    if platform.system() == "Darwin":
        out = _run(["ifconfig", iface])
        m = re.search(r"inet \d+\.\d+\.\d+\.\d+ netmask (0x[0-9a-fA-F]+)", out)
        if m:
            return str(ipaddress.IPv4Address(int(m.group(1), 16)))
    else:
        out = _run(["ip", "-4", "-o", "addr", "show", "dev", iface])
        m = re.search(r"inet \d+\.\d+\.\d+\.\d+/(\d+)", out)
        if m:
            return str(ipaddress.IPv4Network(f"0.0.0.0/{m.group(1)}", strict=False).netmask)
    return "255.255.255.0"


def lookup(iface: str | None = None, gateway: str | None = None) -> NetInfo:
    """Resolve the interface, local IP/MAC, gateway and subnet in one go."""
    default_iface, src_ip, default_gw = conf.route.route("0.0.0.0")

    if iface is None:
        iface = str(default_iface)
        ip = str(src_ip)
    else:
        ip = get_if_addr(iface) or str(src_ip)
        if not ip or ip == "0.0.0.0":
            raise RuntimeError(f"{iface} uzerinde IPv4 adresi yok")

    mac = get_if_hwaddr(iface)
    if not mac or mac == "00:00:00:00:00:00":
        raise RuntimeError(f"{iface} icin MAC adresi okunamadi")

    gw = gateway or str(default_gw or "")
    if not gw:
        raise RuntimeError("varsayilan gateway bulunamadi, --gateway ile belirtin")

    netmask = netmask_for(iface)
    cidr = str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False))
    return NetInfo(iface=iface, ip=ip, mac=mac, gateway=gw, netmask=netmask, cidr=cidr)
