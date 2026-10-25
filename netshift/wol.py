"""Wake-on-LAN: send a magic packet to a sleeping device."""

from __future__ import annotations

import ipaddress
import shutil
import socket

PORTS = (9, 7)


def magic_packet(mac: str) -> bytes:
    """6 × 0xFF followed by the MAC repeated 16 times (102 bytes)."""
    cleaned = mac.replace(":", "").replace("-", "").replace(".", "").lower()
    if len(cleaned) != 12:
        raise ValueError(f"not a MAC address: {mac}")
    return b"\xff" * 6 + bytes.fromhex(cleaned) * 16


def broadcast_address(ip: str, netmask: str) -> str:
    try:
        return str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False).broadcast_address)
    except ValueError:
        return "255.255.255.255"


def wake(mac: str, iface: str = "", broadcast: str = "255.255.255.255") -> None:
    """Send the packet on every conventional WoL port; any one may get through."""
    packet = magic_packet(mac)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # binding to a device is Linux-only and needs CAP_NET_RAW; it just makes
        # sure the packet leaves on the LAN interface instead of a VPN
        if iface and shutil.which("ip"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, 25, iface.encode() + b"\0")  # SO_BINDTODEVICE
            except OSError:
                pass
        for port in PORTS:
            try:
                sock.sendto(packet, (broadcast, port))
                sock.sendto(packet, ("255.255.255.255", port))
            except OSError:
                pass
