"""Non-blocking delivery of sensor alerts to the hosted NetMask dashboard."""

from __future__ import annotations

import json
import logging
import os
import platform
from concurrent.futures import ThreadPoolExecutor
from urllib import error, request

logger = logging.getLogger("netmask.cloud")


class CloudReporter:
    def __init__(self) -> None:
        self.base_url = os.environ.get("NETMASK_CLOUD_URL", "").strip().rstrip("/")
        self.token = os.environ.get("NETMASK_SENSOR_INGEST_TOKEN", "").strip()
        self.sensor_id = os.environ.get("NETMASK_SENSOR_ID", platform.node() or "unknown-sensor")
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="cloud-report")

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.token)

    def report(self, incident: dict, detection: dict) -> None:
        if self.configured:
            self._executor.submit(self._send, incident, detection)

    def _send(self, incident: dict, detection: dict) -> None:
        payload = dict(incident)
        payload["sensor_id"] = self.sensor_id
        payload["detection"] = detection
        body = json.dumps(payload).encode("utf-8")
        cloud_request = request.Request(
            self.base_url + "/api/sensor/events",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "NetMask-Sensor/1.0",
            },
        )
        try:
            with request.urlopen(cloud_request, timeout=5) as response:
                if response.status != 202:
                    logger.warning("Cloud report returned HTTP %s", response.status)
        except (error.URLError, TimeoutError, OSError) as exc:
            logger.warning("Cloud report delivery failed: %s", exc)

    def create_share(self, incident: dict, *, expires_hours: int = 168) -> dict:
        """Create a public report through the configured hosted dashboard."""
        if not self.configured:
            raise RuntimeError("Connect this sensor to the Azure dashboard before creating a public report link.")
        payload = dict(incident)
        payload["sensor_id"] = self.sensor_id
        payload["expires_hours"] = expires_hours
        cloud_request = request.Request(
            self.base_url + "/api/sensor/share",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "NetMask-Sensor/1.0",
            },
        )
        try:
            with request.urlopen(cloud_request, timeout=10) as response:
                result = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            try:
                result = json.loads(exc.read().decode("utf-8"))
                message = result.get("message") or result.get("error")
            except (ValueError, OSError):
                message = None
            raise RuntimeError(message or f"Hosted report service returned HTTP {exc.code}.") from exc
        except (error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise RuntimeError(f"Could not reach the hosted report service: {exc}") from exc
        if not result.get("success") or not result.get("url"):
            raise RuntimeError("Hosted report service returned an invalid response.")
        return result

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
