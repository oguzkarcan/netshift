"""User-defined device names, stored per MAC.

The name that a device announces (if any) is often cryptic: ``Aqara-Hub-M100-A33E``
or ``Android_Q89LEUJQ``. An alias is what *you* call it — "Salon TV", "Ali'nin
telefonu" — and it always wins over the discovered hostname.

    ~/.config/netshift/aliases.json   {"54:ef:44:90:a3:3e": "Salon TV"}
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

CONFIG = (
    Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    / "netshift"
    / "aliases.json"
)

MAX_LENGTH = 32


def clean_alias(value: str) -> str:
    """Collapse whitespace and drop control characters; an empty result clears."""
    text = re.sub(r"[\x00-\x1f\x7f]", " ", value or "")
    return re.sub(r"\s+", " ", text).strip()[:MAX_LENGTH]


def load() -> dict[str, str]:
    try:
        data = json.loads(CONFIG.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        str(mac).lower(): clean_alias(str(name))
        for mac, name in data.items()
        if clean_alias(str(name))
    }


def save(mapping: dict[str, str]) -> None:
    try:
        CONFIG.parent.mkdir(parents=True, exist_ok=True)
        CONFIG.write_text(
            json.dumps(mapping, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception:
        pass


def get(mac: str) -> str:
    return load().get(mac.lower(), "")


def set_alias(mac: str, name: str) -> str:
    """Store (or clear, when *name* is empty) one alias. Returns the new value."""
    mapping = load()
    cleaned = clean_alias(name)
    if cleaned:
        mapping[mac.lower()] = cleaned
    else:
        mapping.pop(mac.lower(), None)
    save(mapping)
    return cleaned


def apply(devices: list) -> None:
    """Attach aliases to ``Device`` objects (duck-typed to avoid an import cycle)."""
    mapping = load()
    if not mapping:
        return
    for dev in devices:
        dev.alias = mapping.get(dev.mac.lower(), "")
