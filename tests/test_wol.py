"""Wake-on-LAN packet tests: no root, no network required."""

from __future__ import annotations

import unittest

from netshift import wol


class MagicPacket(unittest.TestCase):
    def test_layout(self):
        packet = wol.magic_packet("54:ef:44:90:a3:3e")
        self.assertEqual(len(packet), 102)
        self.assertEqual(packet[:6], b"\xff" * 6)
        self.assertEqual(packet[6:12], bytes.fromhex("54ef4490a33e"))
        self.assertEqual(packet[6:], bytes.fromhex("54ef4490a33e") * 16)

    def test_accepts_dashes_and_uppercase(self):
        self.assertEqual(
            wol.magic_packet("54-EF-44-90-A3-3E"),
            wol.magic_packet("54:ef:44:90:a3:3e"),
        )

    def test_rejects_junk(self):
        with self.assertRaises(ValueError):
            wol.magic_packet("nope")


class Broadcast(unittest.TestCase):
    def test_24_bit_netmask(self):
        self.assertEqual(wol.broadcast_address("192.168.1.20", "255.255.255.0"), "192.168.1.255")

    def test_16_bit_netmask(self):
        self.assertEqual(wol.broadcast_address("10.0.5.9", "255.255.0.0"), "10.0.255.255")

    def test_bad_netmask_falls_back(self):
        self.assertEqual(wol.broadcast_address("10.0.5.9", "junk"), "255.255.255.255")


if __name__ == "__main__":
    unittest.main()
