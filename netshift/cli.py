"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import sys
import time

from . import __version__, aliases, oui, scan, wol
from .netif import NetInfo, lookup
from .poison import STATE_PATH, Poisoner, heal

LAB_NOTICE = """\
netshift is meant for networks you own or are explicitly allowed to administer.
Applying it on someone else's network, to devices whose owners have not agreed,
is unauthorised network interference and disrupts the people using it.
You are responsible for how you run it.
"""


def _need_root() -> None:
    if os.geteuid() != 0:
        sys.exit("Error: sending ARP packets requires root.  Run: sudo netshift ...")


def _duration(text: str) -> int:
    """Parse '90', '90s', '15m', '1h' into seconds."""
    text = text.strip().lower()
    if not text:
        raise argparse.ArgumentTypeError("duration cannot be empty")
    unit = text[-1]
    if unit in "smh":
        number, factor = text[:-1], {"s": 1, "m": 60, "h": 3600}[unit]
    else:
        number, factor = text, 1
    try:
        seconds = int(float(number) * factor)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid duration: {text}") from None
    if seconds <= 0:
        raise argparse.ArgumentTypeError("duration must be positive")
    return seconds


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" + ("" if count == 1 else "s")


def _confirm(net: NetInfo, targets: list[tuple[str, str]]) -> None:
    print(LAB_NOTICE)
    print(f"Network : {net.iface}  {net.ip}/{net.netmask}  (gateway {net.gateway})")
    print("Targets :")
    for ip, mac in targets:
        print(f"          {ip}  {mac}")
    print()
    answer = input("Confirm these devices are under your control. [yes/no] ")
    if answer.strip().lower() not in {"yes", "y"}:
        sys.exit("Cancelled.")


def _install_signal_handlers(poisoner: Poisoner) -> None:
    def handler(_signum, _frame):
        print("\nRestoring...")
        poisoner.stop()
        sys.exit(0)

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(sig, handler)
        except (ValueError, OSError):
            pass


def _resolve_targets(ips: list[str], macs: list[str] | None) -> list[tuple[str, str]]:
    from scapy.all import getmacbyip

    targets: list[tuple[str, str]] = []
    for index, ip in enumerate(ips):
        mac = None
        if macs and index < len(macs):
            mac = macs[index]
        if not mac:
            mac = getmacbyip(ip)
        if not mac:
            sys.exit(f"Error: no MAC address for {ip} (is the device on?).")
        targets.append((ip, mac.lower()))
    return targets


# --------------------------------------------------------------------------
def cmd_scan(args: argparse.Namespace) -> None:
    _need_root()
    net = lookup(args.iface, args.gateway)
    print(f"Network: {net.iface}  {net.ip}/{net.netmask}  gateway {net.gateway}  ({net.cidr})")
    print("ARP scanning...\n")
    devices = scan.arp_scan(net.cidr, net.iface, timeout=args.timeout)
    scan.annotate(devices, net.gateway, net.ip)
    if not args.no_names:
        scan.add_hostnames(devices, net.ip)

    if not devices:
        print("No devices found.")
        return

    print(f"{'IP':<16}{'MAC':<19}{'VENDOR':<24}HOST")
    print("-" * 88)
    for dev in devices:
        flags = []
        if dev.is_gateway:
            flags.append("gateway")
        if dev.is_self:
            flags.append("this machine")
        name = (dev.alias or dev.hostname)[:26]
        marks = f"  [{', '.join(flags)}]" if flags else ""
        vendor = (dev.vendor or "-")[:22]
        print(f"{dev.ip:<16}{dev.mac:<19}{vendor:<24}{name}{marks}")

    total = oui.count()
    suffix = "" if total else "  (run: netshift oui-update)"
    print(f"\n{_plural(len(devices), 'device')}.  OUI database: {total} entries{suffix}")


def cmd_block(args: argparse.Namespace) -> None:
    _need_root()
    net = lookup(args.iface, args.gateway)
    targets = _resolve_targets(args.ip, args.mac)
    if not args.yes:
        _confirm(net, targets)

    poisoner = Poisoner(net, mode=args.mode, interval=args.interval,
                        ipv6=not args.no_ipv6)
    for ip, mac in targets:
        poisoner.add(ip, mac)
    _install_signal_handlers(poisoner)

    poisoner.start()
    what = ("internet cut (the device stays on Wi-Fi)" if args.mode == "block"
            else "traffic relayed through this machine (mitm)")
    print(f"\n{_plural(len(targets), 'device')}: {what}.")
    print("Press Ctrl+C to restore.")

    try:
        if args.duration:
            started = time.time()
            while time.time() - started < args.duration:
                time.sleep(0.5)
            print("\nTime is up, restoring...")
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\nRestoring...")
    finally:
        poisoner.stop()
    print("ARP entries restored.")


def cmd_status(args: argparse.Namespace) -> None:
    """Report a running or leftover session. Deliberately does not need root."""
    if not STATE_PATH.exists():
        print("No active netshift session.")
        return
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        sys.exit(f"Error: cannot read {STATE_PATH}.")

    pid = data.get("pid")
    alive = False
    if isinstance(pid, int):
        try:
            os.kill(pid, 0)
            alive = True
        except ProcessLookupError:
            alive = False
        except PermissionError:      # exists, owned by root
            alive = True

    print(f"Interface : {data.get('iface')}   gateway {data.get('gateway')}   mode {data.get('mode')}")
    if data.get("ipv6"):
        print(f"IPv6      : {data.get('router_ip6') or 'no router advertisement found'}")
    state = "running" if alive else "not running (stale state file)"
    print(f"Process   : {state}" + (f"   pid {pid}" if pid else ""))
    targets = data.get("targets", [])
    print(f"Targets   : {len(targets)}")
    now = time.time()
    for target in targets:
        mac = target.get("mac", "")
        name = aliases.get(mac) or "-"
        deadline = target.get("deadline")
        if deadline:
            left = max(0, int(float(deadline) - now))
            when = f"auto-restore in {left // 60:02d}:{left % 60:02d}"
        else:
            when = "until stopped"
        print(f"  {target.get('ip', ''):<16}{mac:<19}{name:<22}{when}")
    if not alive:
        print("\nThis state is stale; run: sudo netshift heal")


def _looks_like_mac(text: str) -> bool:
    return bool(re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", text))


def cmd_alias(args: argparse.Namespace) -> None:
    """List, set or clear the names shown instead of discovered hostnames."""
    if args.target is None:
        mapping = aliases.load()
        if not mapping:
            print('No aliases yet. Example: netshift alias 192.168.1.42 "Living room TV"')
            return
        for mac, name in sorted(mapping.items()):
            print(f"{mac}  {name}")
        return

    if _looks_like_mac(args.target):
        mac = args.target.lower()
    else:
        _need_root()
        from scapy.all import getmacbyip

        mac = getmacbyip(args.target)
        if not mac:
            sys.exit(f"Error: no MAC address for {args.target} (is the device on?).")
        mac = mac.lower()

    name = "" if args.clear else " ".join(args.name)
    value = aliases.set_alias(mac, name)
    if value:
        print(f"{mac}  →  “{value}”")
    else:
        print(f"Alias cleared for {mac}.")


def cmd_wake(args: argparse.Namespace) -> None:
    """Send a Wake-on-LAN magic packet to an IP or a MAC."""
    net = lookup(args.iface, args.gateway)
    if _looks_like_mac(args.target):
        mac = args.target.lower()
    else:
        _need_root()
        from scapy.all import getmacbyip

        mac = getmacbyip(args.target)
        if not mac:
            sys.exit(f"Error: no MAC address for {args.target} (is the device on?).")
        mac = mac.lower()
    wol.wake(mac, net.iface, wol.broadcast_address(net.ip, net.netmask))
    print(f"Magic packet sent to {mac} via {net.iface}.")


def cmd_heal(args: argparse.Namespace) -> None:
    _need_root()
    print(heal())


def cmd_tui(args: argparse.Namespace) -> None:
    _need_root()
    from .tui import run_tui

    net = lookup(args.iface, args.gateway)
    run_tui(net, mode=args.mode, interval=args.interval, scan_timeout=args.timeout,
            ipv6=not args.no_ipv6)


def cmd_oui(args: argparse.Namespace) -> None:
    print("Downloading the IEEE OUI registry...")
    count = oui.update()
    print(f"{count} entries written to {oui.CACHE}.")


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netshift",
        description="Devices that stay on Wi-Fi but lose the internet: an ARP demo for authorized labs.",
        epilog=LAB_NOTICE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"netshift {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--iface", help="network interface (default: the outgoing one)")
    common.add_argument("--gateway", help="gateway IP (default: from the routing table)")
    common.add_argument("--timeout", type=float, default=1.5, help="ARP scan timeout in seconds")
    common.add_argument("--interval", type=float, default=1.5, help="poison interval in seconds")

    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", parents=[common], help="list the devices on the network")
    p_scan.add_argument("--no-names", action="store_true", help="skip hostname resolution")
    p_scan.set_defaults(func=cmd_scan)

    def add_cut_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("ip", nargs="+", help="target IP addresses")
        p.add_argument("--mac", nargs="+", help="target MAC addresses (same order as the IPs)")
        p.add_argument("--duration", type=_duration, help="restore automatically after: 90s, 15m, 1h")
        p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
        p.add_argument("--no-ipv6", action="store_true",
                       help="do not poison IPv6 neighbour discovery")

    p_block = sub.add_parser("block", parents=[common], help="cut internet for the given devices")
    add_cut_args(p_block)
    p_block.set_defaults(func=cmd_block, mode="block")

    p_mitm = sub.add_parser(
        "mitm", parents=[common], help="relay traffic through this machine (classroom demo)"
    )
    add_cut_args(p_mitm)
    p_mitm.set_defaults(func=cmd_block, mode="mitm")

    p_status = sub.add_parser("status", help="show the active session and its timers")
    p_status.set_defaults(func=cmd_status)

    p_alias = sub.add_parser("alias", help="give a device a name of your own (per MAC)")
    p_alias.add_argument("target", nargs="?", help="IP address, or a MAC address")
    p_alias.add_argument("name", nargs="*", help="the new name; omit to list aliases")
    p_alias.add_argument("--clear", action="store_true", help="remove the alias")
    p_alias.set_defaults(func=cmd_alias)

    p_wake = sub.add_parser("wake", parents=[common], help="wake a sleeping device (Wake-on-LAN)")
    p_wake.add_argument("target", help="IP address, or a MAC address")
    p_wake.set_defaults(func=cmd_wake)

    p_heal = sub.add_parser("heal", help="repair ARP entries left behind by a crashed session")
    p_heal.set_defaults(func=cmd_heal)

    p_tui = sub.add_parser("tui", parents=[common], help="interactive device list")
    p_tui.add_argument("--mode", choices=("block", "mitm"), default="block")
    p_tui.add_argument("--no-ipv6", action="store_true",
                       help="do not poison IPv6 neighbour discovery")
    p_tui.set_defaults(func=cmd_tui)

    p_oui = sub.add_parser("oui-update", help="download the IEEE vendor database")
    p_oui.set_defaults(func=cmd_oui)

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        argv = ["tui"]  # arrow keys first: no typing needed
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except RuntimeError as exc:
        sys.exit(f"Error: {exc}")
    except PermissionError:
        sys.exit("Error: permission denied. Run it with sudo.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
