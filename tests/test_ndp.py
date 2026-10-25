"""NDP frame and parser tests: no root, no network required."""

from __future__ import annotations

import unittest

from scapy.all import Ether, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, IPv6

from netshift import ndp, poison
from netshift.netif import NetInfo

NET = NetInfo(
    iface="enp0s3",
    ip="192.168.1.20",
    mac="aa:aa:aa:aa:aa:aa",
    gateway="192.168.1.1",
    netmask="255.255.255.0",
    cidr="192.168.1.0/24",
)
TARGET_MAC = "b6:37:a2:8f:90:9c"
TARGET_IP6 = "fe80::b437:a2ff:fe8f:909c"
ROUTER_IP6 = "fe80::1"
ROUTER_MAC = "3c:6a:d2:90:2c:06"


class Parsers(unittest.TestCase):
    def test_default_route(self):
        text = "default via fe80::1 dev enp7s0 proto ra metric 1024 pref medium\n"
        self.assertEqual(ndp.parse_default_route(text), "fe80::1")

    def test_no_default_route(self):
        self.assertEqual(ndp.parse_default_route("fe80::/64 dev enp7s0 proto kernel\n"), "")

    def test_ip_neigh_prefers_link_local(self):
        text = (
            "2001:db8::5 lladdr b6:37:a2:8f:90:9c REACHABLE\n"
            "fe80::b437:a2ff:fe8f:909c lladdr b6:37:a2:8f:90:9c STALE\n"
        )
        self.assertEqual(ndp.parse_ip_neigh(text)[TARGET_MAC], TARGET_IP6)

    def test_ndp_filters_by_interface(self):
        text = (
            "fe80::1%en0 3c:6a:d2:90:2c:06 en0 23h S R\n"
            "fe80::2%en1 3c:6a:d2:90:2c:07 en1 23h S\n"
        )
        table = ndp.parse_ndp(text, "en0")
        self.assertEqual(table, {"3c:6a:d2:90:2c:06": "fe80::1"})

    def test_link_local(self):
        text = "    inet6 fe80::b437:a2ff:fe8f:909c/64 scope link\n"
        self.assertEqual(ndp.parse_link_local(text), "fe80::b437:a2ff:fe8f:909c")

    def test_eui64_from_mac(self):
        self.assertEqual(ndp.eui64_link_local(TARGET_MAC), TARGET_IP6)

    def test_eui64_rejects_junk(self):
        self.assertEqual(ndp.eui64_link_local("nope"), "")


class Frames(unittest.TestCase):
    def test_poison_frame_points_at_the_blackhole(self):
        frame = ndp.poison_frame(NET.mac, TARGET_MAC, TARGET_IP6, ROUTER_IP6)
        self.assertEqual(frame[Ether].dst, TARGET_MAC)
        self.assertEqual(frame[IPv6].src, ROUTER_IP6)
        self.assertEqual(frame[IPv6].dst, TARGET_IP6)
        self.assertEqual(frame[IPv6].hlim, 255)
        advertisement = frame[ICMPv6ND_NA]
        self.assertEqual(advertisement.tgt, ROUTER_IP6)
        self.assertEqual(advertisement.O, 1)
        self.assertEqual(frame[ICMPv6NDOptDstLLAddr].lladdr, ndp.BLACKHOLE_MAC)

    def test_restore_frame_uses_the_real_router_mac(self):
        frame = ndp.restore_frame(NET.mac, TARGET_MAC, TARGET_IP6, ROUTER_IP6, ROUTER_MAC)
        self.assertEqual(frame[ICMPv6NDOptDstLLAddr].lladdr, ROUTER_MAC)


class PoisonerFrames(unittest.TestCase):
    def make(self) -> poison.Poisoner:
        p = poison.Poisoner(NET, mode="block", ipv6=True)
        p.gw_mac = ROUTER_MAC
        p.router_ip6 = ROUTER_IP6
        p.add("192.168.1.31", TARGET_MAC)
        p.targets["192.168.1.31"].ip6 = TARGET_IP6
        return p

    def test_poison_frames_include_ndp(self):
        advertisements = [
            frame for frame in self.make()._poison_frames() if ICMPv6ND_NA in frame
        ]
        self.assertEqual(len(advertisements), 1)
        self.assertEqual(
            advertisements[0][ICMPv6NDOptDstLLAddr].lladdr, poison.BLACKHOLE_MAC
        )

    def test_restore_frames_include_ndp(self):
        advertisements = [
            frame for frame in self.make()._restore_frames(NET.gateway, ROUTER_MAC)
            if ICMPv6ND_NA in frame
        ]
        self.assertEqual(len(advertisements), 1)
        self.assertEqual(advertisements[0][ICMPv6NDOptDstLLAddr].lladdr, ROUTER_MAC)

    def test_disabled_ipv6_sends_only_arp(self):
        p = self.make()
        p.ipv6 = False
        self.assertFalse(any(ICMPv6ND_NA in frame for frame in p._poison_frames()))


if __name__ == "__main__":
    unittest.main()


class RouterFallback(unittest.TestCase):
    def test_router_flag_in_neighbour_table(self):
        text = (
            "fe80::1 dev enp7s0 lladdr 3c:6a:d2:90:2c:06 router REACHABLE\n"
            "fe80::2 dev enp7s0 lladdr b6:37:a2:8f:90:9c STALE\n"
        )
        self.assertEqual(ndp.parse_router_neighbor(text), "fe80::1")

    def test_no_router(self):
        self.assertEqual(ndp.parse_router_neighbor("fe80::2 lladdr b6:37:a2:8f:90:9c STALE"), "")
