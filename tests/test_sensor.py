import unittest
from unittest.mock import patch

from scapy.layers.inet import IP, TCP

from flow.Flow import Flow
from netmask.sensor import packet_to_info


class SensorFeatureTests(unittest.TestCase):
    def test_tcp_psh_and_window_are_extracted_from_tcp_layer(self):
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=443, flags="PA", window=4096)
        packet.time = 10.0
        with patch("flow.PacketInfo._process_for_ports", return_value=(None, "")):
            info = packet_to_info(packet)
        self.assertTrue(info.getPSHFlag())
        self.assertFalse(info.getURGFlag())
        self.assertEqual(info.getWinBytes(), 4096)
        self.assertEqual(Flow(info).flowFeatures.getFwdPSHFlags(), 1)


if __name__ == "__main__":
    unittest.main()