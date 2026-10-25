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
netshift yalnızca sahibi olduğunuz veya yazılı izniniz olan ağlarda kullanılmalıdır.
Başkasının ağında, haberleri olmayan cihazlara uygulamak yetkisiz ağ müdahalesidir
ve oradaki insanların işini keser. Devam etme sorumluluğu kullanıcıdadır.
"""


def _need_root() -> None:
    if os.geteuid() != 0:
        sys.exit("Hata: ARP paketi göndermek için root gerekli.  sudo netshift ...")


def _duration(text: str) -> int:
    """Parse '90', '90s', '15m', '1h' into seconds."""
    text = text.strip().lower()
    if not text:
        raise argparse.ArgumentTypeError("süre boş olamaz")
    unit = text[-1]
    if unit in "smh":
        number, factor = text[:-1], {"s": 1, "m": 60, "h": 3600}[unit]
    else:
        number, factor = text, 1
    try:
        seconds = int(float(number) * factor)
    except ValueError:
        raise argparse.ArgumentTypeError(f"geçersiz süre: {text}") from None
    if seconds <= 0:
        raise argparse.ArgumentTypeError("süre pozitif olmalı")
    return seconds


def _hhmmss(seconds: float) -> str:
    seconds = int(seconds)
    return f"{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"


def _confirm(net: NetInfo, targets: list[tuple[str, str]]) -> None:
    print(LAB_NOTICE)
    print(f"Ağ     : {net.iface}  {net.ip}/{net.netmask}  (gateway {net.gateway})")
    print("Hedef  :")
    for ip, mac in targets:
        print(f"         {ip}  {mac}")
    print()
    answer = input("Bu cihazların sizin kontrolünüzde olduğunu onaylıyor musunuz? [evet/hayır] ")
    if answer.strip().lower() not in {"evet", "e", "yes", "y"}:
        sys.exit("İptal edildi.")


def _install_signal_handlers(poisoner: Poisoner) -> None:
    def handler(_signum, _frame):
        print("\nGeri alınıyor...")
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
            sys.exit(f"Hata: {ip} için MAC adresi bulunamadı (cihaz açık mı?).")
        targets.append((ip, mac.lower()))
    return targets


# --------------------------------------------------------------------------
def cmd_scan(args: argparse.Namespace) -> None:
    _need_root()
    net = lookup(args.iface, args.gateway)
    print(f"Ağ: {net.iface}  {net.ip}/{net.netmask}  gateway {net.gateway}  ({net.cidr})")
    print("ARP taraması yapılıyor...\n")
    devices = scan.arp_scan(net.cidr, net.iface, timeout=args.timeout)
    scan.annotate(devices, net.gateway, net.ip)
    if not args.no_names:
        scan.add_hostnames(devices)

    if not devices:
        print("Cihaz bulunamadı.")
        return

    print(f"{'IP':<16}{'MAC':<19}{'ÜRETİCİ':<24}HOST")
    print("-" * 88)
    for dev in devices:
        flags = []
        if dev.is_gateway:
            flags.append("gateway")
        if dev.is_self:
            flags.append("bu makine")
        name = dev.hostname[:26]
        marks = f"  [{', '.join(flags)}]" if flags else ""
        vendor = (dev.vendor or "-")[:22]
        print(f"{dev.ip:<16}{dev.mac:<19}{vendor:<24}{name}{marks}")
    print(f"\n{len(devices)} cihaz.  OUI veritabanı: {oui.count()} kayıt"
          + ("" if oui.count() else "  (netshift oui-update ile indirilebilir)"))


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
    mode_text = "internet kesildi (cihaz Wi-Fi'da kalıyor)" if args.mode == "block" else "trafik bu makineden geçiyor (mitm)"
    print(f"\n{len(targets)} cihaz için {mode_text}.")
    print("Ctrl+C ile geri alınır.")

    try:
        if args.duration:
            started = time.time()
            while time.time() - started < args.duration:
                time.sleep(0.5)
            print("\nSüre doldu, geri alınıyor...")
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\nGeri alınıyor...")
    finally:
        poisoner.stop()
    print("ARP kayıtları geri yüklendi.")


def cmd_heal(args: argparse.Namespace) -> None:
    _need_root()
    print(heal())


def cmd_tui(args: argparse.Namespace) -> None:
    _need_root()
    from .tui import run_tui

    net = lookup(args.iface, args.gateway)
    run_tui(net, mode=args.mode, interval=args.interval, scan_timeout=args.timeout)


def cmd_oui(args: argparse.Namespace) -> None:
    print("IEEE OUI veritabanı indiriliyor...")
    count = oui.update()
    print(f"{count} kayıt {oui.CACHE} dosyasına yazıldı.")


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netshift",
        description="Wi-Fi'da kalan ama interneti kesilen cihazlar: yetkili laboratuvarlar için ARP demosu.",
        epilog=LAB_NOTICE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"netshift {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--iface", help="ağ arayüzü (varsayılan: çıkış arayüzü)")
    common.add_argument("--gateway", help="gateway IP (varsayılan: yönlendirme tablosu)")
    common.add_argument("--timeout", type=float, default=3.0, help="ARP tarama süresi (sn)")
    common.add_argument("--interval", type=float, default=1.5, help="zehirleme periyodu (sn)")

    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", parents=[common], help="ağdaki cihazları listele")
    p_scan.add_argument("--no-names", action="store_true", help="ters DNS sorgusunu atla")
    p_scan.set_defaults(func=cmd_scan)

    def add_cut_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("ip", nargs="+", help="hedef IP adresleri")
        p.add_argument("--mac", nargs="+", help="hedef MAC adresleri (IP sırasıyla)")
        p.add_argument("--duration", type=_duration, help="otomatik geri açma süresi: 90s, 15m, 1h")
        p.add_argument("--yes", action="store_true", help="onay sormadan başla")

    p_block = sub.add_parser("block", parents=[common], help="seçili cihazların internetini kes")
    add_cut_args(p_block)
    p_block.set_defaults(func=cmd_block, mode="block")

    p_mitm = sub.add_parser(
        "mitm", parents=[common], help="trafiği bu makineden geçir (derste 'neden çalışıyor' demosu)"
    )
    add_cut_args(p_mitm)
    p_mitm.set_defaults(func=cmd_block, mode="mitm")

    p_heal = sub.add_parser("heal", help="çökmüş bir oturumdan sonra ARP kayıtlarını onar")
    p_heal.set_defaults(func=cmd_heal)

    p_tui = sub.add_parser("tui", parents=[common], help="etkileşimli cihaz listesi")
    p_tui.add_argument("--mode", choices=("block", "mitm"), default="block")
    p_tui.set_defaults(func=cmd_tui)

    p_oui = sub.add_parser("oui-update", help="IEEE üretici veritabanını indir")
    p_oui.set_defaults(func=cmd_oui)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except RuntimeError as exc:
        sys.exit(f"Hata: {exc}")
    except PermissionError:
        sys.exit("Hata: yetki yok. sudo ile çalıştırın.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
