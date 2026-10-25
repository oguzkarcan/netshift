"""Hostname resolver tests: no root, no network required.

    python -m unittest discover -s tests
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from netshift import names


def nbns_reply(*entries: tuple[str, int, int]) -> bytes:
    """Build an NBNS node-status reply: header, name count, 18-byte entries."""
    header = bytes(12)
    body = bytes([len(entries)])
    for name, suffix, flags in entries:
        body += name.encode("cp437").ljust(15, b" ")[:15]
        body += bytes([suffix]) + flags.to_bytes(2, "big")
    return header + body


class Cleaning(unittest.TestCase):
    def test_local_suffix_is_dropped(self):
        self.assertEqual(names.clean_name("Aqara-Hub-M100-A33E.local."), "Aqara-Hub-M100-A33E")

    def test_lan_suffix_is_dropped(self):
        self.assertEqual(names.clean_name("  nas.lan "), "nas")

    def test_empty_input(self):
        self.assertEqual(names.clean_name(""), "")

    def test_ptr_maps_back_to_ip(self):
        self.assertEqual(names._ptr_to_ip("2.50.168.192.in-addr.arpa."), "192.168.50.2")

    def test_non_ptr_is_ignored(self):
        self.assertIsNone(names._ptr_to_ip("example.com"))


class Nbns(unittest.TestCase):
    def test_workstation_name_wins(self):
        reply = nbns_reply(("DESKTOP-7", 0x00, 0), ("WORKGROUP", 0x00, 0x8000))
        self.assertEqual(names.parse_nbns_status(reply), "DESKTOP-7")

    def test_group_name_is_skipped(self):
        reply = nbns_reply(("WORKGROUP", 0x00, 0x8000), ("NAS", 0x20, 0))
        self.assertEqual(names.parse_nbns_status(reply), "NAS")

    def test_short_or_empty_reply(self):
        self.assertEqual(names.parse_nbns_status(b""), "")
        self.assertEqual(names.parse_nbns_status(bytes(13)), "")


class Cache(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hosts.json"
            with mock.patch.object(names, "CACHE", path):
                names.save_cache({"aa:bb:cc:dd:ee:ff": "phone"})
                self.assertEqual(names.load_cache(), {"aa:bb:cc:dd:ee:ff": "phone"})

    def test_missing_file_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(names, "CACHE", Path(tmp) / "nope.json"):
                self.assertEqual(names.load_cache(), {})

    def test_broken_file_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hosts.json"
            path.write_text("{not json", encoding="utf-8")
            with mock.patch.object(names, "CACHE", path):
                self.assertEqual(names.load_cache(), {})


if __name__ == "__main__":
    unittest.main()
