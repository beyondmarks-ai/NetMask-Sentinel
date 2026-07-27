import os
import unittest

os.environ["CAPTURE_ENABLED"] = "false"
os.environ["ENABLE_GUEST_ACCESS"] = "true"
os.environ["ENABLE_DEBUG_ROUTES"] = "true"

import application


class RouteTests(unittest.TestCase):
    def setUp(self):
        application.app.config.update(TESTING=True)
        self.client = application.app.test_client()

    def authenticate(self):
        self.client.get("/health/live")
        with self.client.session_transaction() as browser_session:
            browser_session["logged_in"] = True
            browser_session["user_id"] = "test-user"
            browser_session["csrf_token"] = "test-token"

    def test_liveness_and_readiness_without_capture(self):
        self.assertEqual(self.client.get("/health/live").status_code, 200)
        ready = self.client.get("/health/ready")
        self.assertEqual(ready.status_code, 200)
        self.assertEqual(ready.get_json()["status"], "ready")

    def test_protected_api_requires_authentication(self):
        self.assertEqual(self.client.get("/api/incidents").status_code, 401)

    def test_incident_acknowledgement_requires_csrf_and_changes_status(self):
        self.authenticate()
        incident = application.incident_manager.record(
            classification="Test Scan", source_ip="10.1.1.1", destination_ip="10.1.1.2",
            protocol="TCP", risk_level="high", attack_probability=0.9, flow_id="test"
        )
        route = f"/api/incidents/{incident.incident_id}/acknowledge"
        self.assertEqual(self.client.post(route).status_code, 400)
        response = self.client.post(route, headers={"X-CSRF-Token": "test-token"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["incident"]["status"], "acknowledged")

    def test_guest_access_opens_dashboard_in_development(self):
        response = self.client.get("/guest", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Recent Incidents", response.data)


if __name__ == "__main__":
    unittest.main()