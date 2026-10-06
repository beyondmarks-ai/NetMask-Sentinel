import os
import unittest
import uuid
from dataclasses import replace
from unittest.mock import patch

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

    def test_local_signup_and_login_work_without_firebase(self):
        self.client.get("/signup")
        with self.client.session_transaction() as browser_session:
            csrf_token = browser_session["csrf_token"]
        suffix = uuid.uuid4().hex[:12]
        email = f"route-test-local-auth-{suffix}@example.test"
        signup = self.client.post(
            "/signup",
            data={
                "csrf_token": csrf_token,
                "username": f"route_test_{suffix}",
                "email": email,
                "fullname": "Route Test",
                "password": "a-long-test-password",
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(signup.status_code, 200)
        self.assertTrue(signup.get_json()["success"])

        self.client.get("/logout")
        self.client.get("/")
        with self.client.session_transaction() as browser_session:
            csrf_token = browser_session["csrf_token"]
        login = self.client.post(
            "/login",
            data={"csrf_token": csrf_token, "username": email, "password": "a-long-test-password"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(login.status_code, 200)
        self.assertTrue(login.get_json()["success"])

    def test_detail_keeps_network_fields_when_explanation_is_unavailable(self):
        self.authenticate()
        original_flows = application.flow_df
        row = [777, *([0] * 39), "10.0.0.7", "443", "10.0.0.8", "51515", "TCP",
               "2026-01-01 00:00:00", "2026-01-01 00:01:00", "test.exe", "1234",
               "Benign", 0.99, "Minimal"]
        application.flow_df = application.pd.DataFrame([row], columns=application.cols)
        try:
            with patch("application.load_explanation_assets", side_effect=RuntimeError("not installed")):
                response = self.client.get("/detail?flow_id=777")
        finally:
            application.flow_df = original_flows
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"10.0.0.7", response.data)
        self.assertIn(b"10.0.0.8", response.data)
        self.assertIn(b"Optional model explanation is unavailable", response.data)

    def test_authorized_lab_alert_records_tester_ip(self):
        with patch.object(application, "settings", replace(application.settings, lab_alert_token="test-lab-token")):
            response = self.client.post(
                "/api/lab-alert",
                headers={"X-NetMask-Lab-Token": "test-lab-token"},
                environ_base={"REMOTE_ADDR": "192.168.50.12"},
            )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["success"])
        self.assertEqual(payload["source_ip"], "192.168.50.12")
        self.assertEqual(payload["incident"]["classification"], "Authorized Lab Alert")


if __name__ == "__main__":
    unittest.main()
