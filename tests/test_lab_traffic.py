import unittest
from unittest.mock import patch
import netmask_lab_traffic

class LabTrafficSafetyTests(unittest.TestCase):
    def test_allows_private_and_loopback_addresses(self):
        for address in ("127.0.0.1", "10.1.2.3", "172.16.1.2", "192.168.20.4", "fd00::1"):
            self.assertTrue(netmask_lab_traffic.is_allowed_lab_address(address))
    def test_rejects_public_targets(self):
        self.assertFalse(netmask_lab_traffic.is_allowed_lab_address("8.8.8.8"))
        with patch("netmask_lab_traffic.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("8.8.8.8", 0))]):
            with self.assertRaises(ValueError):
                netmask_lab_traffic.resolve_private_target("public.example")
    def test_url_host_wraps_ipv6(self):
        self.assertEqual(netmask_lab_traffic.host_for_url("fd00::1"), "[fd00::1]")
        self.assertEqual(netmask_lab_traffic.host_for_url("192.168.1.2"), "192.168.1.2")

if __name__ == "__main__":
    unittest.main()