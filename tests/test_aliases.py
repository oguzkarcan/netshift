"""Alias store and device naming: no root, no network required."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from netshift import aliases
from netshift.scan import Device

MAC = "54:ef:44:90:a3:3e"


class Cleaning(unittest.TestCase):
    def test_whitespace_is_collapsed(self):
        self.assertEqual(aliases.clean_alias("  Living   room\tTV "), "Living room TV")

    def test_control_characters_are_dropped(self):
        self.assertEqual(aliases.clean_alias("bad\x00name\x1b"), "bad name")

    def test_length_is_capped(self):
        self.assertEqual(len(aliases.clean_alias("x" * 100)), aliases.MAX_LENGTH)

    def test_empty_clears(self):
        self.assertEqual(aliases.clean_alias("   "), "")


class Store(unittest.TestCase):
    def test_set_and_clear(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(aliases, "CONFIG", Path(tmp) / "aliases.json"):
                self.assertEqual(aliases.set_alias(MAC.upper(), "  Salon TV "), "Salon TV")
                self.assertEqual(aliases.get(MAC), "Salon TV")
                self.assertEqual(aliases.set_alias(MAC, ""), "")
                self.assertEqual(aliases.get(MAC), "")

    def test_broken_file_reads_as_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "aliases.json"
            path.write_text("{nope", encoding="utf-8")
            with mock.patch.object(aliases, "CONFIG", path):
                self.assertEqual(aliases.load(), {})

    def test_apply_attaches_alias_by_mac(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(aliases, "CONFIG", Path(tmp) / "aliases.json"):
                aliases.set_alias(MAC, "Salon TV")
                machines = [Device("192.168.1.42", MAC, "Lumi", "Aqara-Hub")]
                aliases.apply(machines)
                self.assertEqual(machines[0].alias, "Salon TV")


class Naming(unittest.TestCase):
    def test_alias_wins_over_hostname(self):
        dev = Device("192.168.1.42", MAC, "Lumi", "Aqara-Hub")
        self.assertEqual(dev.name, "Aqara-Hub")
        dev.alias = "Salon TV"
        self.assertEqual(dev.name, "Salon TV")

    def test_unknown_device_has_no_name(self):
        self.assertEqual(Device("192.168.1.42", MAC).name, "")


if __name__ == "__main__":
    unittest.main()
