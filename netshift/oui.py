"""Small offline MAC vendor lookup backed by the IEEE OUI registry.

`netshift update-oui` downloads the public registry once; scanning works
without it (vendors are simply left blank).
"""

from __future__ import annotations

import csv
import io
import os
import urllib.request
from pathlib import Path

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
CACHE = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "netshift" / "oui.csv"

_DB: dict[str, str] | None = None


def _load() -> dict[str, str]:
    global _DB
    if _DB is not None:
        return _DB
    _DB = {}
    if CACHE.exists():
        try:
            with CACHE.open(newline="", encoding="utf-8", errors="replace") as fh:
                for row in csv.DictReader(fh):
                    key = (row.get("Assignment") or "").strip().upper()
                    name = (row.get("Organization Name") or "").strip()
                    if key:
                        _DB[key] = name
        except Exception:
            pass
    return _DB


def update(timeout: int = 45) -> int:
    """Download the IEEE OUI registry and return the number of entries."""
    global _DB
    req = urllib.request.Request(OUI_URL, headers={"User-Agent": "netshift/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_bytes(raw)
    _DB = None
    return len(_load())


def vendor(mac: str) -> str:
    """Return the vendor name for *mac*, or an empty string."""
    key = mac.replace(":", "").replace("-", "").upper()[:6]
    return _load().get(key, "")


def count() -> int:
    return len(_load())
