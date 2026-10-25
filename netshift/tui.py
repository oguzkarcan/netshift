"""Curses TUI: pick devices, cut their internet, put it back."""

from __future__ import annotations

import curses
import signal
import time

from . import scan
from .netif import NetInfo
from .poison import Poisoner


class App:
    def __init__(self, net: NetInfo, mode: str = "block", interval: float = 1.5,
                 scan_timeout: float = 3.0) -> None:
        self.net = net
        self.mode = mode
        self.interval = interval
        self.scan_timeout = scan_timeout
        self.devices: list[scan.Device] = []
        self.cursor = 0
        self.selected: set[str] = set()
        self.poisoner = Poisoner(net, mode=mode, interval=interval)
        self.cut_since: dict[str, float] = {}
        self.message = "Hazır. Boşluk ile seç, 'b' ile kes."
        self.running = True

    # -- data --------------------------------------------------------------
    def refresh(self) -> None:
        devices = scan.arp_scan(self.net.cidr, self.net.iface, timeout=self.scan_timeout)
        scan.annotate(devices, self.net.gateway, self.net.ip)
        scan.add_hostnames(devices, timeout=1.5)
        self.devices = devices
        # keep the pointer stable and drop selection of disappeared devices
        alive = {d.ip for d in devices}
        self.selected &= alive
        self.cursor = max(0, min(self.cursor, len(devices) - 1))

    @property
    def cut(self) -> set[str]:
        return set(self.poisoner.targets)

    # -- actions -----------------------------------------------------------
    def cut_selected(self) -> None:
        if not self.selected:
            self.message = "Önce hedef seç (boşluk)."
            return
        added = 0
        for dev in self.devices:
            if dev.ip in self.selected and dev.ip not in self.poisoner.targets and not dev.is_gateway:
                self.poisoner.add(dev.ip, dev.mac)
                self.cut_since[dev.ip] = time.time()
                added += 1
        if not added:
            self.message = "Seçili cihazların hepsi zaten kesik."
            return
        if not self.poisoner.active:
            try:
                self.poisoner.start()
            except Exception as exc:  # no route, no gateway MAC, no permission
                self.message = f"Başlatılamadı: {exc}"
                return
        self.message = f"{added} cihazın interneti kesildi. Wi-Fi bağlantıları duruyor."

    def restore_all(self) -> None:
        if not self.poisoner.targets:
            self.message = "Geri alınacak cihaz yok."
            return
        count = len(self.poisoner.targets)
        self.poisoner.stop()
        self.poisoner.targets.clear()
        self.cut_since.clear()
        self.message = f"{count} cihazın ARP kaydı geri yüklendi."

    # -- drawing -----------------------------------------------------------
    def _draw(self, stdscr: curses.window) -> None:
        stdscr.erase()
        height, width = stdscr.getmaxyx()

        title = f" netshift · {self.mode} · {self.net.iface} {self.net.ip}/{self.net.netmask} · gw {self.net.gateway} "
        try:
            stdscr.attron(curses.A_REVERSE)
            stdscr.addnstr(0, 0, title.ljust(width)[:width], width)
            stdscr.attroff(curses.A_REVERSE)
        except curses.error:
            pass

        header = f"{'':2}{'IP':<16}{'MAC':<19}{'ÜRETİCİ':<20}{'HOST':<20}DURUM"
        if height > 3:
            stdscr.addnstr(2, 0, header[:width], width, curses.A_BOLD)

        body_height = max(0, height - 6)
        start = 0
        if self.cursor >= body_height:
            start = self.cursor - body_height + 1

        for row, dev in enumerate(self.devices[start:start + body_height]):
            index = start + row
            marker = ">" if index == self.cursor else " "
            box = "[x]" if dev.ip in self.selected else "[ ]"
            if dev.ip in self.poisoner.targets:
                state = "KESİK " + self._elapsed(dev.ip)
            elif dev.is_gateway:
                state = "gateway"
            elif dev.is_self:
                state = "bu makine"
            else:
                state = "açık"
            vendor = (dev.vendor or "-")[:18]
            host = (dev.hostname or "-")[:18]
            line = f"{marker}{box}{dev.ip:<16}{dev.mac:<19}{vendor:<20}{host:<20}{state}"
            attr = curses.A_REVERSE if index == self.cursor else curses.A_NORMAL
            if dev.ip in self.poisoner.targets:
                attr |= curses.A_BOLD
            try:
                stdscr.addnstr(3 + row, 0, line.ljust(width)[:width], width, attr)
            except curses.error:
                break

        cut_total = len(self.poisoner.targets)
        status = (f" {len(self.devices)} cihaz · {cut_total} kesik · {len(self.selected)} seçili "
                  f"| boşluk: seç  b: kes  r: geri aç  s: yenile  q: çık ")
        try:
            stdscr.attron(curses.A_REVERSE)
            stdscr.addnstr(height - 2, 0, status.ljust(width)[:width], width)
            stdscr.attroff(curses.A_REVERSE)
            stdscr.addnstr(height - 1, 0, (" " + self.message)[:width], width)
        except curses.error:
            pass
        stdscr.refresh()

    def _elapsed(self, ip: str) -> str:
        started = self.cut_since.get(ip)
        if not started:
            return ""
        seconds = int(time.time() - started)
        return f"{seconds // 60:02d}:{seconds % 60:02d}"

    # -- loop --------------------------------------------------------------
    def _main(self, stdscr: curses.window) -> None:
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.keypad(True)

        def on_signal(_signum, _frame):
            self.running = False

        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            try:
                signal.signal(sig, on_signal)
            except (ValueError, OSError):
                pass

        last_scan = 0.0
        while self.running:
            if time.time() - last_scan > 15:
                self.message = "Ağ taranıyor..."
                self._draw(stdscr)
                self.refresh()
                last_scan = time.time()
                self.message = "Hazır."

            self._draw(stdscr)
            try:
                key = stdscr.getch()
            except curses.error:
                key = -1

            if key in (curses.KEY_UP, ord("k")):
                self.cursor = max(0, self.cursor - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                self.cursor = min(len(self.devices) - 1, self.cursor + 1)
            elif key == ord(" "):
                if self.devices:
                    ip = self.devices[self.cursor].ip
                    if ip in self.selected:
                        self.selected.discard(ip)
                    else:
                        self.selected.add(ip)
            elif key in (ord("b"), ord("x")):
                self.cut_selected()
            elif key == ord("r"):
                self.restore_all()
            elif key in (ord("s"), ord("R")):
                self.message = "Ağ taranıyor..."
                self._draw(stdscr)
                self.refresh()
                self.message = "Hazır."
            elif key in (ord("q"), 27):
                self.running = False
            time.sleep(0.05)

    def run(self) -> None:
        try:
            curses.wrapper(self._main)
        finally:
            self.poisoner.stop()


def run_tui(net: NetInfo, mode: str = "block", interval: float = 1.5,
            scan_timeout: float = 3.0) -> None:
    App(net, mode=mode, interval=interval, scan_timeout=scan_timeout).run()
