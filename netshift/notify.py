"""Best-effort desktop notifications (GNOME/KDE, macOS).

``sudo`` keeps the caller's environment only partially, so a notification may
simply not be possible: every failure here is silent on purpose. Disable with
``NETSHIFT_NOTIFY=0``.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import threading


def _enabled() -> bool:
    return os.environ.get("NETSHIFT_NOTIFY", "1").lower() not in {"0", "false", "no", "off"}


def _send(title: str, body: str, timeout: int) -> None:
    if platform.system() == "Darwin":
        if not shutil.which("osascript"):
            return
        script = f"display notification {json.dumps(body)} with title {json.dumps(title)}"
        subprocess.run(["osascript", "-e", script], capture_output=True, timeout=5)
        return

    binary = shutil.which("notify-send")
    if not binary:
        return
    if not any(os.environ.get(key) for key in ("DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS")):
        return
    subprocess.run(
        [binary, "-a", "netshift", "-t", str(timeout), title, body],
        capture_output=True,
        timeout=5,
    )


def desktop(title: str, body: str, timeout: int = 4000) -> None:
    """Fire and forget, so a slow notification daemon never stalls the UI."""
    if not _enabled():
        return

    def run() -> None:
        try:
            _send(title, body, timeout)
        except Exception:
            pass

    threading.Thread(target=run, name="netshift-notify", daemon=True).start()
