import csv
import os
import tempfile
import unittest
import uuid
from dataclasses import replace
from pathlib import Path
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

    def test_landing_only_offers_login_and_signup(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="heroLoginBtn"', response.data)
        self.assertIn(b'id="heroSignupBtn"', response.data)
        self.assertNotIn(b"Skip - View Dashboard", response.data)

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

    def test_signup_explains_password_requirement(self):
        page = self.client.get("/")
        self.assertIn(b'minlength="12"', page.data)
        with self.client.session_transaction() as browser_session:
            csrf_token = browser_session["csrf_token"]
        response = self.client.post(
            "/signup",
            data={
                "csrf_token": csrf_token,
                "username": "short_password_user",
                "email": "short-password@example.test",
                "fullname": "Short Password",
                "password": "short",
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["errors"]["password"], "Password must be at least 12 characters")

    def test_login_browser_script_submits_csrf_token(self):
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'name="csrf_token"', page.data)
        self.assertIn(b"data: $form.serialize()", page.data)
        self.assertNotIn(b"data: formData,", page.data)

    def test_dashboard_socket_uses_secure_same_origin_url(self):
        script = application.app.static_folder + "/js/application.js"
        with open(script, "r", encoding="utf-8") as source:
            javascript = source.read()
        self.assertIn("typeof io === \"function\" ? io('/test'", javascript)
        self.assertNotIn("io.connect('http://'", javascript)
        self.assertIn("setInterval(refreshIncidents, 5000)", javascript)
        self.assertIn("latestIncidentItems", javascript)
        self.authenticate()
        dashboard = self.client.get("/capture")
        self.assertIn(f"application.js?v={application.asset_version}".encode(), dashboard.data)
        self.assertIn(f"main.css?v={application.asset_version}".encode(), dashboard.data)
        self.assertIn(f"simple-charts.js?v={application.asset_version}".encode(), dashboard.data)
        for element_id in (
            b'id="analyzed-flows"',
            b'id="attack-rate"',
            b'id="average-confidence"',
            b'id="high-risk-flows"',
            b'id="myChart"',
            b'id="riskChart"',
        ):
            self.assertIn(element_id, dashboard.data)
        self.assertIn("refreshDashboardAnalytics()", javascript)
        self.assertIn("incident.max_attack_probability", javascript)
        self.assertIn("Report link ready", javascript)
        self.assertIn("copy-report-link", javascript)
        self.assertNotIn('await navigator.clipboard.writeText(payload.url)', javascript)

    def test_recent_flow_history_restores_details_and_latest_duplicate(self):
        first = {column: "0" for column in application.cols}
        first.update({"FlowID": "41", "Src": "10.0.0.1", "Dest": "10.0.0.2",
                      "Protocol": "TCP", "Classification": "Benign", "Probability": "0.9", "Risk": "Minimal"})
        latest = dict(first)
        latest["Src"] = "10.0.0.99"
        latest["Probability"] = "0.99"
        with tempfile.TemporaryDirectory() as directory:
            history_path = Path(directory) / "captured_flows.csv"
            with history_path.open("w", newline="", encoding="utf-8") as destination:
                writer = csv.DictWriter(destination, fieldnames=application.cols)
                writer.writeheader()
                writer.writerow(first)
                writer.writerow(latest)
            restored = application._load_recent_flow_history(history_path)
        self.assertEqual(len(restored), 1)
        self.assertEqual(int(restored.iloc[0]["FlowID"]), 41)
        self.assertEqual(restored.iloc[0]["Src"], "10.0.0.99")

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

    def test_cloud_sensor_ingestion_requires_token_and_preserves_observed_ips(self):
        event = {
            "source_ip": "203.0.113.44",
            "destination_ip": "10.0.0.12",
            "classification": "Probe",
            "protocol": "TCP",
            "risk_level": "high",
            "max_attack_probability": 0.91,
            "sensor_id": "branch-office-1",
            "latest_flow_id": "42",
        }
        hosted_settings = replace(application.settings, sensor_ingest_token="x" * 48)
        with patch.object(application, "settings", hosted_settings), patch("application.azure_store.save_incident") as save:
            denied = self.client.post("/api/sensor/events", json=event)
            accepted = self.client.post(
                "/api/sensor/events",
                json=event,
                headers={"Authorization": f"Bearer {'x' * 48}"},
            )
        self.assertEqual(denied.status_code, 401)
        self.assertEqual(accepted.status_code, 202)
        saved = save.call_args.args[0]
        self.assertEqual(saved["source_ip"], "203.0.113.44")
        self.assertEqual(saved["destination_ip"], "10.0.0.12")
        self.assertEqual(saved["sensor_id"], "branch-office-1")

    def test_authenticated_user_can_create_expiring_share_link(self):
        self.authenticate()
        incident = application.incident_manager.record(
            classification="Probe", source_ip="198.51.100.9", destination_ip="10.0.0.4",
            protocol="TCP", risk_level="high", attack_probability=0.88, flow_id="share-test"
        )
        route = f"/api/incidents/{incident.incident_id}/share"
        with patch("application.azure_store.configured", return_value=True), patch(
            "application.azure_store.get_incident", return_value=incident.to_dict()
        ), patch(
            "application.azure_store.create_share",
            return_value=("secret-share-token", "2030-01-01T00:00:00+00:00"),
        ):
            response = self.client.post(route, headers={"X-CSRF-Token": "test-token"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("/share/secret-share-token", response.get_json()["url"])

    def test_local_share_uses_configured_hosted_dashboard(self):
        self.authenticate()
        incident = application.incident_manager.record(
            classification="Authorized Test", source_ip="192.168.1.20", destination_ip="192.168.1.8",
            protocol="TCP", risk_level="high", attack_probability=0.95, flow_id="local-share-test"
        )
        hosted = {
            "success": True,
            "url": "https://dashboard.example/share/hosted-token",
            "expires_at": "2030-01-01T00:00:00+00:00",
        }
        with patch("application.azure_store.configured", return_value=False), patch.object(
            application.cloud_reporter, "create_share", return_value=hosted
        ) as create_share:
            response = self.client.post(
                f"/api/incidents/{incident.incident_id}/share",
                headers={"X-CSRF-Token": "test-token"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["url"], hosted["url"])
        create_share.assert_called_once()

    def test_sensor_can_create_hosted_share_with_bearer_token(self):
        payload = {
            "incident_id": "INC-SENSOR-1", "classification": "Probe",
            "source_ip": "192.168.1.20", "destination_ip": "192.168.1.8",
            "protocol": "TCP", "risk_level": "high", "event_count": 1,
            "max_attack_probability": 0.91, "sensor_id": "sensor-a",
        }
        hosted_settings = replace(application.settings, sensor_ingest_token="x" * 48)
        with patch.object(application, "settings", hosted_settings), patch(
            "application.azure_store.configured", return_value=True
        ), patch(
            "application.azure_store.create_share",
            return_value=("sensor-share-token", "2030-01-01T00:00:00+00:00"),
        ):
            denied = self.client.post("/api/sensor/share", json=payload)
            accepted = self.client.post(
                "/api/sensor/share", json=payload,
                headers={"Authorization": f"Bearer {'x' * 48}"},
            )
        self.assertEqual(denied.status_code, 401)
        self.assertEqual(accepted.status_code, 200)
        self.assertIn("/share/sensor-share-token", accepted.get_json()["url"])

    def test_public_share_page_displays_observed_source_ip(self):
        report = {
            "incident_id": "INC-1", "classification": "Probe", "source_ip": "198.51.100.9",
            "destination_ip": "10.0.0.4", "protocol": "TCP", "risk_level": "high",
            "max_attack_probability": 0.88, "first_seen": "now", "last_seen": "now",
            "event_count": 1, "sensor_id": "sensor-a",
        }
        with patch("application.azure_store.resolve_share", return_value=report):
            response = self.client.get("/share/test-token")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"198.51.100.9", response.data)
        self.assertIn(b"Observed source IP", response.data)


if __name__ == "__main__":
    unittest.main()
