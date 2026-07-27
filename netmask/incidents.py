"""Thread-safe in-memory incident correlation for live detections."""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITY_ORDER = {"minimal": 0, "low": 1, "medium": 2, "high": 3, "very_high": 4}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Incident:
    incident_id: str
    key: str
    classification: str
    source_ip: str
    destination_ip: str
    protocol: str
    risk_level: str
    status: str = "new"
    event_count: int = 1
    first_seen: datetime = field(default_factory=_utc_now)
    last_seen: datetime = field(default_factory=_utc_now)
    max_attack_probability: float = 0.0
    latest_flow_id: int | str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["first_seen"] = self.first_seen.isoformat()
        payload["last_seen"] = self.last_seen.isoformat()
        return payload


class IncidentManager:
    """Groups repeated alerts by class/source/destination/protocol in a time window."""

    def __init__(self, *, window_seconds: int = 120, max_incidents: int = 500) -> None:
        if window_seconds <= 0:
            raise ValueError("Incident window must be positive")
        self.window_seconds = window_seconds
        self._incidents: deque[Incident] = deque(maxlen=max_incidents)
        self._active_by_key: dict[str, Incident] = {}
        self._counter = 0
        self._lock = threading.RLock()

    @staticmethod
    def correlation_key(
        classification: str, source_ip: str, destination_ip: str, protocol: str
    ) -> str:
        return "|".join(
            value.strip().lower()
            for value in (classification, source_ip, destination_ip, protocol)
        )

    def record(
        self,
        *,
        classification: str,
        source_ip: str,
        destination_ip: str,
        protocol: str,
        risk_level: str,
        attack_probability: float,
        flow_id: int | str | None,
        occurred_at: datetime | None = None,
    ) -> Incident:
        now = occurred_at or _utc_now()
        key = self.correlation_key(classification, source_ip, destination_ip, protocol)
        with self._lock:
            existing = self._active_by_key.get(key)
            if existing and (now - existing.last_seen).total_seconds() <= self.window_seconds:
                existing.event_count += 1
                existing.last_seen = now
                existing.latest_flow_id = flow_id
                existing.max_attack_probability = max(
                    existing.max_attack_probability, float(attack_probability)
                )
                if SEVERITY_ORDER.get(risk_level, -1) > SEVERITY_ORDER.get(existing.risk_level, -1):
                    existing.risk_level = risk_level
                return existing

            self._counter += 1
            incident = Incident(
                incident_id=f"INC-{now:%Y%m%d}-{self._counter:06d}",
                key=key,
                classification=classification,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                risk_level=risk_level,
                first_seen=now,
                last_seen=now,
                max_attack_probability=float(attack_probability),
                latest_flow_id=flow_id,
            )
            self._incidents.appendleft(incident)
            self._active_by_key[key] = incident
            return incident

    def list(self, *, limit: int = 100, status: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            values = list(self._incidents)
            if status:
                values = [incident for incident in values if incident.status == status]
            return [incident.to_dict() for incident in values[: max(0, limit)]]

    def acknowledge(self, incident_id: str) -> dict[str, Any] | None:
        with self._lock:
            for incident in self._incidents:
                if incident.incident_id == incident_id:
                    incident.status = "acknowledged"
                    return incident.to_dict()
        return None

    def summary(self) -> dict[str, int]:
        with self._lock:
            return {
                "total": len(self._incidents),
                "new": sum(item.status == "new" for item in self._incidents),
                "acknowledged": sum(item.status == "acknowledged" for item in self._incidents),
                "high_or_above": sum(
                    SEVERITY_ORDER.get(item.risk_level, 0) >= SEVERITY_ORDER["high"]
                    for item in self._incidents
                ),
            }