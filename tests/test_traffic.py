"""Traffic counter and DNS observation tests: no root, no network required."""

from __future__ import annotations

import unittest

from scapy.all import DNS, DNSQR, Ether, IP, UDP

from netshift.traffic import Monitor, human_rate

CLIENT = "192.168.1.42"
GATEWAY = "192.168.1.1"


def query(name: str, src: str = CLIENT) -> Ether:
    return (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff")
        / IP(src=src, dst=GATEWAY)
        / UDP(sport=5555, dport=53)
        / DNS(id=1, rd=1, qd=DNSQR(qname=name))
    )


def answer(name: str) -> Ether:
    return (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff")
        / IP(src=GATEWAY, dst=CLIENT)
        / UDP(sport=53, dport=5555)
        / DNS(id=1, qr=1, qd=DNSQR(qname=name))
    )


class Counting(unittest.TestCase):
    def test_both_endpoints_are_counted(self):
        monitor = Monitor("lo")
        monitor._on_packet(query("example.com"))
        self.assertGreater(monitor._counts[CLIENT], 0)
        self.assertGreater(monitor._counts[GATEWAY], 0)

    def test_tick_moves_counts_into_history(self):
        monitor = Monitor("lo")
        monitor._on_packet(query("example.com"))
        monitor._bucket -= 10
        monitor.tick()
        self.assertGreater(monitor.rate(CLIENT), 0)
        self.assertEqual(len(monitor.series(CLIENT, width=8)), 8)
        self.assertEqual(monitor._counts, {})


class Queries(unittest.TestCase):
    def test_query_is_recorded(self):
        monitor = Monitor("lo")
        monitor._on_packet(query("example.com."))
        recent = monitor.recent()
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0][1], CLIENT)
        self.assertEqual(recent[0][2], "example.com")

    def test_answers_are_ignored(self):
        monitor = Monitor("lo")
        monitor._on_packet(answer("example.com."))
        self.assertEqual(monitor.recent(), [])

    def test_query_count_per_device(self):
        monitor = Monitor("lo")
        monitor._on_packet(query("a.example"))
        monitor._on_packet(query("b.example"))
        monitor._on_packet(query("c.example", src="192.168.1.43"))
        self.assertEqual(monitor.query_count(CLIENT), 2)
        self.assertEqual(monitor.query_count("192.168.1.43"), 1)

    def test_non_dns_udp_is_ignored(self):
        monitor = Monitor("lo")
        packet = (
            Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff")
            / IP(src=CLIENT, dst=GATEWAY)
            / UDP(sport=5555, dport=9999)
            / b"x"
        )
        monitor._on_packet(packet)
        self.assertEqual(monitor.recent(), [])

    def test_clear(self):
        monitor = Monitor("lo")
        monitor._on_packet(query("example.com."))
        monitor.clear()
        self.assertEqual(monitor.recent(), [])


class HumanRate(unittest.TestCase):
    def test_units(self):
        self.assertEqual(human_rate(500), "500 B/s")
        self.assertEqual(human_rate(2048), "2.0 KB/s")
        self.assertEqual(human_rate(3 * 1024 * 1024), "3.0 MB/s")


if __name__ == "__main__":
    unittest.main()
