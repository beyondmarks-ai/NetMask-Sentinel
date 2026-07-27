import os
import unittest
from unittest.mock import patch

from netmask.config import Settings


class ConfigTests(unittest.TestCase):
    def test_production_requires_long_secret(self):
        with patch.dict(os.environ, {"NETMASK_ENV": "production", "FLASK_SECRET_KEY": "short"}, clear=True):
            with self.assertRaises(RuntimeError):
                Settings.from_env()

    def test_production_disallows_debug_capabilities(self):
        env = {"NETMASK_ENV": "production", "FLASK_SECRET_KEY": "x" * 40, "ENABLE_GUEST_ACCESS": "true"}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(RuntimeError):
                Settings.from_env()

    def test_capture_can_be_disabled_for_offline_operation(self):
        with patch.dict(os.environ, {"CAPTURE_ENABLED": "false"}, clear=True):
            self.assertFalse(Settings.from_env().capture_enabled)


if __name__ == "__main__":
    unittest.main()