import unittest
from datetime import datetime, timedelta, timezone

from netmask.incidents import IncidentManager


class IncidentTests(unittest.TestCase):
    def test_related_events_are_correlated_and_severity_escalates(self):
        manager = IncidentManager(window_seconds=60)
        at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        first = manager.record(classification="Scan", source_ip="10.0.0.1", destination_ip="10.0.0.2", protocol="TCP", risk_level="medium", attack_probability=0.5, flow_id=1, occurred_at=at)
        second = manager.record(classification="Scan", source_ip="10.0.0.1", destination_ip="10.0.0.2", protocol="TCP", risk_level="high", attack_probability=0.8, flow_id=2, occurred_at=at + timedelta(seconds=30))
        self.assertEqual(first.incident_id, second.incident_id)
        self.assertEqual(second.event_count, 2)
        self.assertEqual(second.risk_level, "high")
        self.assertEqual(manager.summary()["total"], 1)

    def test_window_creates_new_incident_and_acknowledge_updates_status(self):
        manager = IncidentManager(window_seconds=10)
        at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        first = manager.record(classification="Scan", source_ip="a", destination_ip="b", protocol="TCP", risk_level="high", attack_probability=0.8, flow_id=1, occurred_at=at)
        manager.record(classification="Scan", source_ip="a", destination_ip="b", protocol="TCP", risk_level="high", attack_probability=0.8, flow_id=2, occurred_at=at + timedelta(seconds=11))
        self.assertEqual(manager.summary()["total"], 2)
        acknowledged = manager.acknowledge(first.incident_id)
        self.assertEqual(acknowledged["status"], "acknowledged")


if __name__ == "__main__":
    unittest.main()