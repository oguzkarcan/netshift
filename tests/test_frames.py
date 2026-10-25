"""Frame-level tests: no root, no network required.

    python -m unittest discover -s tests
"""

from __future__ import annotations

import unittest

from scapy.all import ARP, Ether

from netshift.cli import _duration
from netshift.netif import NetInfo
from netshift.poison import BLACKHOLE_MAC, Poisoner

NET = NetInfo(
    iface="enp0s3",
    ip="192.168.1.20",
    mac="aa:aa:aa:aa:aa:aa",
    gateway="192.168.1.1",
    netmask="255.255.255.0",
    cidr="192.168.1.0/24",
)
GW_MAC = "bb:bb:bb:bb:bb:bb"
TARGET_MAC = "cc:cc:cc:cc:cc:cc"


def make(mode: str = "block") -> Poisoner:
    poisoner = Poisoner(NET, mode=mode)
    poisoner.gw_mac = GW_MAC
    poisoner.add("192.168.1.42", TARGET_MAC)
    return poisoner


class BlockMode(unittest.TestCase):
    def test_target_is_told_gateway_has_a_dead_mac(self):
        frames = make()._poison_frames()
        self.assertEqual(len(frames), 1)
        frame = frames[0]
        self.assertIsInstance(frame, Ether)
        self.assertEqual(frame.dst, TARGET_MAC)
        self.assertEqual(frame[ARP].op, 2)  # ARP reply
        self.assertEqual(frame[ARP].psrc, NET.gateway)
        self.assertEqual(frame[ARP].hwsrc, BLACKHOLE_MAC)
        self.assertEqual(frame[ARP].pdst, "192.168.1.42")

    def test_blackhole_mac_is_not_a_real_vendor_prefix(self):
        self.assertTrue(BLACKHOLE_MAC.startswith("02:"))  # locally administered, unicast

    def test_gateway_cannot_be_a_target(self):
        with self.assertRaises(ValueError):
            make().add(NET.gateway, GW_MAC)


class MitmMode(unittest.TestCase):
    def test_both_sides_are_poisoned_with_our_mac(self):
        frames = make("mitm")._poison_frames()
        self.assertEqual(len(frames), 2)
        to_target = [f for f in frames if f.dst == TARGET_MAC][0]
        to_gateway = [f for f in frames if f.dst == GW_MAC][0]
        self.assertEqual(to_target[ARP].hwsrc, NET.mac)
        self.assertEqual(to_target[ARP].psrc, NET.gateway)
        self.assertEqual(to_gateway[ARP].hwsrc, NET.mac)
        self.assertEqual(to_gateway[ARP].psrc, "192.168.1.42")


class Restore(unittest.TestCase):
    def test_real_mappings_are_restored(self):
        frames = make()._restore_frames(NET.gateway, GW_MAC)
        self.assertEqual(len(frames), 3)
        unicast = [f for f in frames if f.dst == TARGET_MAC][0]
        self.assertEqual(unicast[ARP].hwsrc, GW_MAC)
        self.assertEqual(unicast[ARP].psrc, NET.gateway)
        gratuitous = [f for f in frames if f.dst == "ff:ff:ff:ff:ff:ff"][0]
        self.assertEqual(gratuitous[ARP].hwsrc, TARGET_MAC)


class Durations(unittest.TestCase):
    def test_formats(self):
        self.assertEqual(_duration("90"), 90)
        self.assertEqual(_duration("90s"), 90)
        self.assertEqual(_duration("15m"), 900)
        self.assertEqual(_duration("1h"), 3600)
        self.assertEqual(_duration("0.5m"), 30)

    def test_rejects_junk(self):
        for bad in ("", "abc", "0", "-5m"):
            with self.assertRaises(Exception):
                _duration(bad)


if __name__ == "__main__":
    unittest.main()
