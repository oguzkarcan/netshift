"""Curses TUI: a proper terminal interface for netshift.

Everything is driven by the keyboard (arrows + single letters); no command
line typing is needed once the app is open. Scans run in a background thread
so the interface never freezes.
"""

from __future__ import annotations

import curses
import locale
import signal
import threading
import time

from . import scan
from .netif import NetInfo
from .poison import Poisoner

locale.setlocale(locale.LC_ALL, "")

_UNICODE = "UTF-8" in locale.getpreferredencoding(False).upper()
G = (
    {"tl": "╭", "tr": "╮", "bl": "╰", "br": "╯", "h": "─", "v": "│",
     "dot": "●", "cursor": "▌", "check": "✓", "cross": "✗", "bullet": "·"}
    if _UNICODE
    else {"tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "-", "v": "|",
          "dot": "*", "cursor": ">", "check": "x", "cross": "x", "bullet": "-"}
)

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if _UNICODE else "|/-\\"

HELP_LINES = [
    ("", ""),
    ("  ↑ ↓ / j k", "move between devices"),
    ("  space", "select / deselect a device"),
    ("  b", "cut internet for the selected devices"),
    ("  r", "restore every cut device"),
    ("  s", "rescan the network"),
    ("  m", "switch mode: block ↔ mitm"),
    ("  enter", "device details"),
    ("  ?", "this screen"),
    ("  q", "quit (restores everything first)"),
]


class Palette:
    """Colour pairs, with a graceful fallback on monochrome terminals."""

    def __init__(self) -> None:
        self.enabled = False
        self.attr: dict[str, int] = {}
        if not curses.has_colors():
            return
        try:
            curses.start_color()
            try:
                curses.use_default_colors()
                bg = -1
            except curses.error:
                bg = curses.COLOR_BLACK
            pairs = {
                "border": (curses.COLOR_CYAN, bg),
                "title": (curses.COLOR_CYAN, bg),
                "dim": (curses.COLOR_BLUE, bg),
                "ok": (curses.COLOR_GREEN, bg),
                "cut": (curses.COLOR_RED, bg),
                "accent": (curses.COLOR_YELLOW, bg),
                "text": (curses.COLOR_WHITE, bg),
                "sel": (curses.COLOR_BLACK, curses.COLOR_CYAN),
                "badge": (curses.COLOR_BLACK, curses.COLOR_YELLOW),
            }
            for index, (name, (fg, background)) in enumerate(pairs.items(), start=1):
                curses.init_pair(index, fg, background)
                self.attr[name] = curses.color_pair(index)
            self.enabled = True
        except curses.error:
            self.attr = {}

    def __getitem__(self, name: str) -> int:
        return self.attr.get(name, 0)


class Scanner:
    """Run ARP scans off the UI thread."""

    def __init__(self, net: NetInfo, timeout: float) -> None:
        self.net = net
        self.timeout = timeout
        self.devices: list[scan.Device] = []
        self.error = ""
        self._thread: threading.Thread | None = None
        self._revision = 0

    @property
    def busy(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def revision(self) -> int:
        return self._revision

    def start(self, names: bool = True) -> None:
        if self.busy:
            return
        self._thread = threading.Thread(target=self._run, args=(names,), daemon=True)
        self._thread.start()

    def _run(self, names: bool) -> None:
        try:
            devices = scan.arp_scan(self.net.cidr, self.net.iface, timeout=self.timeout)
            scan.annotate(devices, self.net.gateway, self.net.ip)
            if names:
                scan.add_hostnames(devices, timeout=1.5)
            self.devices = devices
            self.error = ""
        except Exception as exc:  # permission, no route, ...
            self.error = str(exc) or exc.__class__.__name__
        finally:
            self._revision += 1


class App:
    def __init__(self, net: NetInfo, mode: str = "block", interval: float = 1.5,
                 scan_timeout: float = 3.0) -> None:
        self.net = net
        self.mode = mode
        self.interval = interval
        self.scanner = Scanner(net, scan_timeout)
        self.poisoner = Poisoner(net, mode=mode, interval=interval)
        self.cursor = 0
        self.selected: set[str] = set()
        self.cut_since: dict[str, float] = {}
        self.screen = "main"          # main | confirm | help | details
        self.toast = ""
        self.toast_until = 0.0
        self.running = True
        self._revision = -1
        self._frame = 0

    # -- state helpers -----------------------------------------------------
    @property
    def devices(self) -> list[scan.Device]:
        return self.scanner.devices

    def focused(self) -> scan.Device | None:
        if not self.devices:
            return None
        return self.devices[max(0, min(self.cursor, len(self.devices) - 1))]

    def notify(self, text: str, seconds: float = 4.0) -> None:
        self.toast = text
        self.toast_until = time.time() + seconds

    def sync_scan(self) -> None:
        if self.scanner.revision == self._revision:
            return
        self._revision = self.scanner.revision
        alive = {d.ip for d in self.devices}
        self.selected &= alive
        self.cursor = max(0, min(self.cursor, len(self.devices) - 1))

    # -- actions -----------------------------------------------------------
    def toggle(self) -> None:
        dev = self.focused()
        if dev is None:
            return
        if dev.is_gateway or dev.is_self:
            self.notify("The gateway and this machine cannot be targeted.", 3)
            return
        self.selected.symmetric_difference_update({dev.ip})

    def ask_cut(self) -> None:
        if not self.selected:
            self.notify("Select a target with space first.", 3)
            return
        self.screen = "confirm"

    def apply_cut(self) -> None:
        self.screen = "main"
        added: list[str] = []
        for dev in self.devices:
            if dev.ip in self.selected and dev.ip not in self.poisoner.targets:
                if dev.is_gateway:
                    continue
                self.poisoner.add(dev.ip, dev.mac)
                self.cut_since[dev.ip] = time.time()
                added.append(dev.ip)
        if not added:
            self.notify("The selected devices are already cut.", 3)
            return
        try:
            self.poisoner.start()
        except Exception as exc:
            for ip in added:
                self.poisoner.remove(ip)
                self.cut_since.pop(ip, None)
            self.notify(f"Could not start: {exc}", 6)
            return
        self.selected.clear()
        noun = "device" if len(added) == 1 else "devices"
        self.notify(f"{len(added)} {noun} cut — Wi-Fi stays connected.", 6)

    def restore_all(self) -> None:
        count = len(self.poisoner.targets)
        if not count:
            self.notify("Nothing to restore.", 3)
            return
        self.poisoner.stop()
        self.poisoner.targets.clear()
        self.cut_since.clear()
        noun = "device" if count == 1 else "devices"
        self.notify(f"ARP entries restored for {count} {noun}.", 5)

    def toggle_mode(self) -> None:
        if self.poisoner.active:
            self.notify("Restore first (r) before switching mode.", 4)
            return
        self.mode = "mitm" if self.mode == "block" else "block"
        self.poisoner = Poisoner(self.net, mode=self.mode, interval=self.interval)
        detail = ("traffic is relayed through this machine" if self.mode == "mitm"
                  else "devices stay on Wi-Fi and lose the internet")
        self.notify(f"Mode: {self.mode} — {detail}", 5)

    def rescan(self) -> None:
        if self.scanner.busy:
            self.notify("A scan is already running…", 2)
            return
        self.scanner.start()
        self.notify("Scanning the network…", 2)

    # -- low level drawing -------------------------------------------------
    @staticmethod
    def put(win: curses.window, y: int, x: int, text: str, attr: int = 0,
            width: int | None = None) -> None:
        height, cols = win.getmaxyx()
        if not 0 <= y < height or x >= cols or x < 0:
            return
        limit = cols - x if width is None else min(width, cols - x)
        if limit <= 0:
            return
        try:
            win.addnstr(y, x, text, limit, attr)
        except curses.error:
            pass

    def hline(self, win: curses.window, y: int, width: int, left: str = "",
              right: str = "", title: str = "", label_right: str = "",
              attr: int = 0) -> None:
        inner = max(0, width - 2)
        body = list(G["h"] * inner)
        if title:
            label = f" {title} "[:inner]
            body[: len(label)] = label
        if label_right:
            label = f" {label_right} "[:inner]
            start = max(0, inner - len(label))
            body[start:start + len(label)] = label
        self.put(win, y, 0, left + "".join(body) + right, attr, width)

    # -- panels ------------------------------------------------------------
    def draw_frame(self, win: curses.window, pal: Palette) -> tuple[int, int]:
        height, width = win.getmaxyx()
        border = pal["border"]

        self.hline(win, 0, width, G["tl"], G["tr"], "netshift", self.mode, border)
        info = (f" {self.net.iface}  {self.net.ip}/{self.net.netmask}"
                f"   gw {self.net.gateway}")
        self.put(win, 1, 0, G["v"], border)
        self.put(win, 1, 1, info, pal["dim"], width - 2)
        count = f"{len(self.devices)} devices "
        self.put(win, 1, max(1, width - len(count) - 1), count, pal["text"], len(count))
        self.put(win, 1, width - 1, G["v"], border)
        self.hline(win, 2, width, "├", "┤", "", "", border)

        for y in range(3, height - 3):
            self.put(win, y, 0, G["v"], border)
            self.put(win, y, width - 1, G["v"], border)

        self.hline(win, height - 3, width, "├", "┤", "", "", border)
        self.hline(win, height - 1, width, G["bl"], G["br"], "", "", border)
        return height, width

    def draw_table(self, win: curses.window, pal: Palette, height: int, width: int,
                   right_bound: int) -> None:
        top = 3
        bottom = height - 3
        rows = max(0, bottom - top - 1)
        wide = right_bound >= 100
        medium = right_bound >= 74

        header = " " * 5 + f"{'#':>2}  "
        if wide:
            header += f"{'HOST':<19}{'IP':<16}{'MAC':<18}{'VENDOR':<20}"
        elif medium:
            header += f"{'HOST':<20}{'IP':<16}"
        else:
            header += f"{'IP':<16}"
        self.put(win, top, 1, header, pal["dim"] | curses.A_BOLD, right_bound - 2)

        if not self.devices:
            self.draw_empty(win, pal, top + 1, bottom)
            return

        start = 0
        if self.cursor >= rows:
            start = self.cursor - rows + 1

        for offset, dev in enumerate(self.devices[start:start + rows]):
            index = start + offset
            y = top + 1 + offset
            focused = index == self.cursor
            cut = dev.ip in self.poisoner.targets
            checked = dev.ip in self.selected

            mark = G["cursor"] if focused else " "
            box = "[x]" if checked else "[ ]"
            state = f"{G['dot']} {self.state_text(dev, cut)}"

            if wide:
                vendor = (dev.vendor or "-")[:18]
                host = (dev.hostname or "-")[:18]
                body = f"{mark}{box} {index + 1:>2}  {host:<19}{dev.ip:<16}{dev.mac:<18}{vendor:<20}"
            elif medium:
                host = (dev.hostname or "-")[:18]
                body = f"{mark}{box} {index + 1:>2}  {host:<20}{dev.ip:<16}"
            else:
                body = f"{mark}{box} {index + 1:>2}  {dev.ip:<16}"

            if focused:
                attr = pal["sel"] | curses.A_BOLD
            elif cut:
                attr = pal["cut"] | curses.A_BOLD
            elif dev.is_gateway or dev.is_self:
                attr = pal["dim"]
            else:
                attr = pal["ok"]
            self.put(win, y, 1, body.ljust(right_bound - 2), attr, right_bound - 2)
            self.put(win, y, max(1, right_bound - len(state) - 1), state, attr | curses.A_BOLD)

        if self.scanner.busy:
            spin = SPINNER[self._frame % len(SPINNER)]
            label = f"{spin} scanning "
            self.put(win, height - 3, max(2, width - len(label) - 3), label, pal["accent"])

    def state_text(self, dev: scan.Device, cut: bool) -> str:
        if cut:
            started = self.cut_since.get(dev.ip)
            if started:
                seconds = int(time.time() - started)
                return f"CUT {seconds // 60:02d}:{seconds % 60:02d}"
            return "CUT"
        if dev.is_gateway:
            return "gateway"
        if dev.is_self:
            return "this machine"
        return "up"

    def draw_empty(self, win: curses.window, pal: Palette, top: int, bottom: int) -> None:
        message = "Scanning…" if self.scanner.busy else "No devices found — press s to rescan"
        if self.scanner.error:
            message = f"Scan failed: {self.scanner.error[:60]}"
        self.put(win, (top + bottom) // 2, 3, message, pal["accent"])

    def draw_footer(self, win: curses.window, pal: Palette, height: int, width: int) -> None:
        if self.toast and time.time() < self.toast_until:
            text = " " + self.toast
            attr = pal["accent"] | curses.A_BOLD
        else:
            text = " space select · b cut · r restore · s rescan · m mode · ? help · q quit "
            attr = pal["dim"]
        self.put(win, height - 2, 1, text, attr, width - 2)

    def draw_details(self, win: curses.window, pal: Palette, height: int, left: int,
                     width: int) -> None:
        dev = self.focused()
        if dev is None or left >= width - 1:
            return
        panel = width - left - 1
        top = 3
        bottom = height - 3
        for y in range(top, bottom):
            self.put(win, y, left, G["v"] + " " * (panel - 1), pal["border"])
        self.put(win, top, left + 2, "DETAILS", pal["title"] | curses.A_BOLD, panel - 3)

        label_w = 10
        lines = [
            ("Host", dev.hostname or "-"),
            ("IP", dev.ip),
            ("MAC", dev.mac),
            ("Vendor", dev.vendor or "-"),
            ("State", self.state_text(dev, dev.ip in self.poisoner.targets)),
            ("Selected", "yes" if dev.ip in self.selected else "no"),
        ]
        for offset, (label, value) in enumerate(lines, start=2):
            y = top + offset
            if y >= bottom - 1:
                break
            self.put(win, y, left + 2, f"{label:<{label_w}}{value}", pal["text"], panel - 2)

    # -- modals ------------------------------------------------------------
    def draw_modal(self, win: curses.window, pal: Palette, title: str, lines: list[tuple[str, int]],
                   footer: str, width: int = 60) -> None:
        height, cols = win.getmaxyx()
        panel_w = min(width, cols - 4)
        panel_h = len(lines) + 4
        top = max(1, (height - panel_h) // 2)
        left = max(1, (cols - panel_w) // 2)

        # blank the full rows behind the dialog so stray table text
        # does not peek out around its edges
        for y in range(top, min(top + panel_h, height - 1)):
            self.put(win, y, 1, " " * (cols - 2), 0, cols - 2)

        for y in range(top, min(top + panel_h, height)):
            self.put(win, y, left, " " * panel_w, pal["title"])
        self.put(win, top, left, G["tl"] + G["h"] * (panel_w - 2) + G["tr"], pal["title"])
        self.put(win, top, left + 1, f"{G['h']} {title} ", pal["title"] | curses.A_BOLD, panel_w - 2)
        self.put(win, top + panel_h - 1, left, G["bl"] + G["h"] * (panel_w - 2) + G["br"], pal["title"])
        for offset, (text, attr) in enumerate(lines, start=1):
            self.put(win, top + offset, left + 1, " " + text.ljust(panel_w - 3), attr, panel_w - 2)
        self.put(win, top + panel_h - 2, left + 1, " " + footer.ljust(panel_w - 3), pal["accent"], panel_w - 2)

    def draw_confirm(self, win: curses.window, pal: Palette) -> None:
        targets = [d for d in self.devices if d.ip in self.selected]
        noun = "device" if len(targets) == 1 else "devices"
        lines: list[tuple[str, int]] = [(f"{len(targets)} {noun} will lose internet access:", pal["text"]), ("", 0)]
        for dev in targets[:5]:
            name = dev.hostname or dev.ip
            lines.append((f"  {G['dot']} {name}  ({dev.ip})", pal["cut"]))
        if len(targets) > 5:
            lines.append((f"  … and {len(targets) - 5} more", pal["text"]))
        lines.append(("", 0))
        lines.append(("Wi-Fi stays connected — only the internet goes away.", pal["dim"]))
        self.draw_modal(win, pal, "Confirm", lines,
                        "[Enter] cut     [Esc] cancel", width=64)

    def draw_help(self, win: curses.window, pal: Palette) -> None:
        lines = [(f"{key:<16}{desc}", pal["text"]) for key, desc in HELP_LINES]
        lines.append(("", 0))
        lines.append(("Use only on networks you own or administer.", pal["accent"]))
        self.draw_modal(win, pal, "help", lines, "[Esc] close", width=58)

    def draw_details_modal(self, win: curses.window, pal: Palette) -> None:
        dev = self.focused()
        if dev is None:
            self.screen = "main"
            return
        rows = [
            ("Host", dev.hostname or "-"),
            ("IP", dev.ip),
            ("MAC", dev.mac),
            ("Vendor", dev.vendor or "-"),
            ("State", self.state_text(dev, dev.ip in self.poisoner.targets)),
            ("Gateway", "yes" if dev.is_gateway else "no"),
            ("This machine", "yes" if dev.is_self else "no"),
        ]
        lines = [(f"  {label:<14}{value}", pal["text"]) for label, value in rows]
        self.draw_modal(win, pal, "device details", lines, "[Esc] close", width=62)

    # -- main loop ---------------------------------------------------------
    def draw(self, win: curses.window, pal: Palette) -> None:
        win.erase()
        height, width = self.draw_frame(win, pal)
        panel_left = width - 35 if width >= 110 else width - 1
        self.draw_table(win, pal, height, width, panel_left)
        self.draw_details(win, pal, height, panel_left, width)
        if panel_left < width - 1:
            self.put(win, 2, panel_left, "┬", pal["border"])
            self.put(win, height - 3, panel_left, "┴", pal["border"])
        self.draw_footer(win, pal, height, width)

        if self.screen == "confirm":
            self.draw_confirm(win, pal)
        elif self.screen == "help":
            self.draw_help(win, pal)
        elif self.screen == "details":
            self.draw_details_modal(win, pal)
        win.refresh()

    def handle(self, key: int) -> None:
        if self.screen == "confirm":
            if key in (10, 13, curses.KEY_ENTER, ord("y")):
                self.apply_cut()
            elif key in (27, ord("n")):
                self.screen = "main"
            return
        if self.screen in ("help", "details"):
            if key in (27, ord("q"), ord("?"), 10, 13, curses.KEY_ENTER):
                self.screen = "main"
            return

        if key in (curses.KEY_UP, ord("k")):
            self.cursor = max(0, self.cursor - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            self.cursor = min(len(self.devices) - 1, self.cursor + 1)
        elif key == ord(" "):
            self.toggle()
        elif key in (ord("b"), ord("x")):
            self.ask_cut()
        elif key == ord("r"):
            self.restore_all()
        elif key == ord("s"):
            self.rescan()
        elif key == ord("m"):
            self.toggle_mode()
        elif key in (10, 13, curses.KEY_ENTER):
            self.screen = "details"
        elif key == ord("?"):
            self.screen = "help"
        elif key == ord("q"):
            self.running = False

    def _main(self, win: curses.window) -> None:
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        win.nodelay(True)
        win.keypad(True)
        pal = Palette()

        def on_signal(_signum, _frame):
            self.running = False

        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            try:
                signal.signal(sig, on_signal)
            except (ValueError, OSError):
                pass

        self.scanner.start()
        last_scan = time.time()

        while self.running:
            self.sync_scan()

            if not self.scanner.busy and time.time() - last_scan > 20:
                self.scanner.start()
                last_scan = time.time()
            if not self.scanner.busy:
                last_scan = max(last_scan, time.time() - 1)

            self.draw(win, pal)
            try:
                key = win.getch()
            except curses.error:
                key = -1
            if key != -1:
                self.handle(key)

            self._frame += 1
            time.sleep(0.08)

    def run(self) -> None:
        try:
            curses.set_escdelay(25)  # Esc must feel instant
        except (AttributeError, curses.error):
            pass
        try:
            curses.wrapper(self._main)
        finally:
            self.poisoner.stop()


def run_tui(net: NetInfo, mode: str = "block", interval: float = 1.5,
            scan_timeout: float = 3.0) -> None:
    App(net, mode=mode, interval=interval, scan_timeout=scan_timeout).run()
