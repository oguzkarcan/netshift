"""Command line interface."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time

from . import __version__, oui, scan
from .netif import NetInfo, lookup
from .poison import Poisoner, heal

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
        scan.add_hostnames(devices)

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
        name = dev.hostname[:26]
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

    poisoner = Poisoner(net, mode=args.mode, interval=args.interval)
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


def cmd_heal(args: argparse.Namespace) -> None:
    _need_root()
    print(heal())


def cmd_tui(args: argparse.Namespace) -> None:
    _need_root()
    from .tui import run_tui

    net = lookup(args.iface, args.gateway)
    run_tui(net, mode=args.mode, interval=args.interval, scan_timeout=args.timeout)


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
    common.add_argument("--timeout", type=float, default=3.0, help="ARP scan timeout in seconds")
    common.add_argument("--interval", type=float, default=1.5, help="poison interval in seconds")

    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", parents=[common], help="list the devices on the network")
    p_scan.add_argument("--no-names", action="store_true", help="skip reverse DNS lookups")
    p_scan.set_defaults(func=cmd_scan)

    def add_cut_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("ip", nargs="+", help="target IP addresses")
        p.add_argument("--mac", nargs="+", help="target MAC addresses (same order as the IPs)")
        p.add_argument("--duration", type=_duration, help="restore automatically after: 90s, 15m, 1h")
        p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    p_block = sub.add_parser("block", parents=[common], help="cut internet for the given devices")
    add_cut_args(p_block)
    p_block.set_defaults(func=cmd_block, mode="block")

    p_mitm = sub.add_parser(
        "mitm", parents=[common], help="relay traffic through this machine (classroom demo)"
    )
    add_cut_args(p_mitm)
    p_mitm.set_defaults(func=cmd_block, mode="mitm")

    p_heal = sub.add_parser("heal", help="repair ARP entries left behind by a crashed session")
    p_heal.set_defaults(func=cmd_heal)

    p_tui = sub.add_parser("tui", parents=[common], help="interactive device list")
    p_tui.add_argument("--mode", choices=("block", "mitm"), default="block")
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
