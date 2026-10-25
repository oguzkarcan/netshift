"""Timer state: no root, no network required."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from netshift import poison
from netshift.netif import NetInfo

NET = NetInfo(
    iface="enp0s3",
    ip="192.168.1.20",
    mac="aa:aa:aa:aa:aa:aa",
    gateway="192.168.1.1",
    netmask="255.255.255.0",
    cidr="192.168.1.0/24",
)
TARGET = "192.168.1.31"
TARGET_MAC = "cc:cc:cc:cc:cc:cc"


class Timers(unittest.TestCase):
    def make(self) -> poison.Poisoner:
        return poison.Poisoner(NET)

    def test_add_records_deadline(self):
        p = self.make()
        p.add(TARGET, TARGET_MAC, deadline=1234.5)
        self.assertEqual(p.targets[TARGET].deadline, 1234.5)

    def test_gateway_is_rejected(self):
        with self.assertRaises(ValueError):
            self.make().add(NET.gateway, TARGET_MAC)

    def test_set_deadline_writes_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            with mock.patch.object(poison, "STATE_PATH", path):
                p = self.make()
                p.add(TARGET, TARGET_MAC)
                self.assertTrue(p.set_deadline(TARGET, 99.0))
                data = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(data["targets"][0]["deadline"], 99.0)
                self.assertEqual(data["pid"], __import__("os").getpid())

    def test_set_deadline_for_unknown_target(self):
        self.assertFalse(self.make().set_deadline(TARGET, 99.0))


if __name__ == "__main__":
    unittest.main()
