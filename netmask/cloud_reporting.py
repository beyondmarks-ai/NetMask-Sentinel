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

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
