"""Hostname resolution for LAN devices.

No single method works everywhere, so they are tried in order of cost:

1. the system resolver (PTR from the router, /etc/hosts, mDNS on macOS)
2. a direct mDNS PTR query — ask the device itself
3. ``avahi-resolve``, reusing a running avahi-daemon for devices that only
   answer unicast queries
4. NBNS node status (Windows and Samba hosts)
5. SSDP/UPnP ``friendlyName`` (TVs, printers, NAS boxes)

Devices rarely expose all of these, so the union is what makes hostnames show
up. Resolved names are cached per MAC, which survives DHCP address changes and
keeps names stable across sessions.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path
from typing import TYPE_CHECKING

from scapy.all import DNS, DNSQR

if TYPE_CHECKING:  # avoids a circular import at runtime
    from .scan import Device

CACHE = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "netshift" / "hosts.json"

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
SSDP_GROUP = "239.255.255.250"
SSDP_PORT = 1900


# -- cache -----------------------------------------------------------------
def load_cache() -> dict[str, str]:
    try:
        return json.loads(CACHE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_cache(cache: dict[str, str]) -> None:
    try:
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(cache, indent=2, sort_keys=True), encoding="utf-8")
    except Exception:
        pass


# -- helpers ---------------------------------------------------------------
def clean_name(value: str) -> str:
    """Turn a DNS/NetBIOS/SSDP name into something short and printable."""
    name = (value or "").strip().strip(".")
    if name.lower().endswith(".local"):
        name = name[:-6]
    if name.lower().endswith(".lan") or name.lower().endswith(".home"):
        name = name.rsplit(".", 1)[0]
    return name.strip()


def _reverse_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def _ptr_to_ip(name: str) -> str | None:
    name = name.rstrip(".")
    if not name.endswith(".in-addr.arpa"):
        return None
    parts = name[: -len(".in-addr.arpa")].split(".")
    if len(parts) != 4:
        return None
    return ".".join(reversed(parts))


# -- method 1: system resolver --------------------------------------------
def _gethostbyaddr(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def reverse_dns(devices: list["Device"], timeout: float = 1.5) -> dict[str, str]:
    if not devices:
        return {}
    found: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=min(32, len(devices))) as pool:
        futures = {pool.submit(_gethostbyaddr, d.ip): d.ip for d in devices}
        done, _ = wait(futures, timeout=timeout)
        for future in done:
            ip = futures[future]
            name = clean_name(future.result())
            if name:
                found[ip] = name
    return found


# -- method 2: mDNS PTR ---------------------------------------------------
def mdns_ptr(ips: list[str], iface_ip: str, timeout: float = 1.2) -> dict[str, str]:
    """Send one PTR question per address and collect the multicast answers."""
    if not ips:
        return {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", MDNS_PORT))
        sock.setsockopt(
            socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
            socket.inet_aton(MDNS_GROUP) + socket.inet_aton(iface_ip),
        )
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    except OSError:
        # port taken by a daemon that will not share it: not fatal
        sock.close()
        return {}

    found: dict[str, str] = {}
    try:
        for ip in ips:
            query = bytes(DNS(id=0, rd=0, qd=DNSQR(qname=_reverse_name(ip), qtype="PTR", qclass="IN")))
            sock.sendto(query, (MDNS_GROUP, MDNS_PORT))

        sock.settimeout(0.2)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, _addr = sock.recvfrom(9000)
            except socket.timeout:
                continue
            try:
                packet = DNS(data)
            except Exception:
                continue
            for index in range(packet.ancount):
                answer = packet.an[index]
                try:
                    ip = _ptr_to_ip(answer.rrname.decode("utf-8", "replace"))
                    value = answer.rdata
                    if isinstance(value, bytes):
                        value = value.decode("utf-8", "replace")
                    name = clean_name(str(value))
                except Exception:
                    continue
                if ip and name:
                    found[ip] = name
            if len(found) >= len(ips):
                break
    finally:
        sock.close()
    return found


# -- method 3: avahi-resolve ----------------------------------------------
def avahi_names(ips: list[str], timeout: float = 1.2) -> dict[str, str]:
    binary = shutil.which("avahi-resolve")
    if not binary or not ips:
        return {}

    def one(ip: str) -> tuple[str, str]:
        try:
            out = subprocess.run(
                [binary, "-a", ip], capture_output=True, text=True, timeout=timeout
            ).stdout.split()
        except Exception:
            return ip, ""
        return ip, clean_name(out[1]) if len(out) > 1 else ""

    found: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=min(16, len(ips))) as pool:
        for ip, name in pool.map(one, ips):
            if name:
                found[ip] = name
    return found


# -- method 4: NBNS node status -------------------------------------------
def parse_nbns_status(reply: bytes) -> str:
    """Pick a workstation name out of an NBNS node-status reply."""
    # 12-byte header, then: count(1), count × [name(15) suffix(1) flags(2)]
    if len(reply) < 13:
        return ""
    count = reply[12]
    fallback = ""
    for index in range(min(count, 32)):
        start = 13 + index * 18
        entry = reply[start:start + 18]
        if len(entry) < 18:
            break
        name = entry[:15].decode("cp437", "replace").strip()
        suffix = entry[15]
        flags = int.from_bytes(entry[16:18], "big")
        if not name:
            continue
        if suffix in (0x00, 0x20) and not flags & 0x8000:
            return name
        if not fallback and not flags & 0x8000:
            fallback = name
    return fallback


def nbns_names(ips: list[str], timeout: float = 0.6) -> dict[str, str]:
    """NetBIOS node status: one UDP datagram per host, parsed by hand."""
    if not ips:
        return {}
    try:
        from scapy.layers.netbios import NBNSHeader, NBNSNodeStatusRequest

        query = bytes(NBNSHeader() / NBNSNodeStatusRequest(QUESTION_NAME="*"))
    except Exception:
        return {}

    found: dict[str, str] = {}

    def one(ip: str) -> tuple[str, str]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(query, (ip, 137))
            data, _addr = sock.recvfrom(4096)
            return ip, clean_name(parse_nbns_status(data))
        except Exception:
            return ip, ""
        finally:
            sock.close()

    with ThreadPoolExecutor(max_workers=min(16, len(ips))) as pool:
        for ip, name in pool.map(one, ips):
            if name:
                found[ip] = name
    return found


# -- method 5: SSDP friendlyName ------------------------------------------
def _friendly_name(location: str, timeout: float = 0.8) -> str:
    try:
        with urllib.request.urlopen(location, timeout=timeout) as response:
            body = response.read(65536).decode("utf-8", "replace")
    except Exception:
        return ""
    match = re.search(r"<friendlyName>\s*(.*?)\s*</friendlyName>", body, re.I | re.S)
    return clean_name(match.group(1)) if match else ""


def ssdp_names(ips: list[str], iface_ip: str, timeout: float = 1.2) -> dict[str, str]:
    if not ips:
        return {}

    request = (
        'M-SEARCH * HTTP/1.1\r\n'
        f'HOST: {SSDP_GROUP}:{SSDP_PORT}\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 1\r\n'
        'ST: upnp:rootdevice\r\n\r\n'
    ).encode()

    locations: dict[str, str] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(0.2)
        sock.sendto(request, (SSDP_GROUP, SSDP_PORT))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(9000)
            except socket.timeout:
                continue
            if addr[0] not in ips:
                continue
            text = data.decode("utf-8", "replace")
            match = re.search(r"^location:\s*(\S+)", text, re.I | re.M)
            if match:
                locations[addr[0]] = match.group(1)
    finally:
        sock.close()

    found: dict[str, str] = {}
    if not locations:
        return found
    with ThreadPoolExecutor(max_workers=min(8, len(locations))) as pool:
        futures = {pool.submit(_friendly_name, loc): ip for ip, loc in locations.items()}
        for future, ip in futures.items():
            try:
                name = future.result()
            except Exception:
                continue
            if name:
                found[ip] = name
    return found


# -- orchestration ---------------------------------------------------------
def resolve(devices: list["Device"], iface_ip: str, mtimeout: float = 1.4) -> None:
    """Fill in ``Device.hostname`` using every method that is available."""
    if not devices:
        return

    cache = load_cache()
    for dev in devices:
        if not dev.hostname:
            dev.hostname = cache.get(dev.mac.lower(), "")

    pending = [d for d in devices if not d.hostname]
    if not pending:
        return

    def apply(found: dict[str, str]) -> None:
        for dev in devices:
            if not dev.hostname and found.get(dev.ip):
                dev.hostname = found[dev.ip]

    # the resolver cache and mDNS are independent: ask both at once
    with ThreadPoolExecutor(max_workers=2) as pool:
        by_ptr = pool.submit(reverse_dns, list(pending), min(1.2, mtimeout))
        by_mdns = pool.submit(mdns_ptr, [d.ip for d in pending], iface_ip, min(0.9, mtimeout))
        for future in (by_ptr, by_mdns):
            try:
                apply(future.result())
            except Exception:
                pass

    pending = [d for d in pending if not d.hostname]
    if pending:
        apply(avahi_names([d.ip for d in pending], timeout=min(0.8, mtimeout)))
        pending = [d for d in pending if not d.hostname]
    if pending:
        with ThreadPoolExecutor(max_workers=2) as pool:
            by_nbns = pool.submit(nbns_names, [d.ip for d in pending], 0.4)
            by_ssdp = pool.submit(ssdp_names, [d.ip for d in pending], iface_ip, min(0.8, mtimeout))
            for future in (by_nbns, by_ssdp):
                try:
                    apply(future.result())
                except Exception:
                    pass

    refreshed = False
    for dev in devices:
        if dev.hostname and cache.get(dev.mac.lower()) != dev.hostname:
            cache[dev.mac.lower()] = dev.hostname
            refreshed = True
    if refreshed:
        save_cache(cache)
