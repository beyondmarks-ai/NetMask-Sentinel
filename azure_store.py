"""Azure Table Storage persistence for accounts, incidents, and expiring shares."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any


def _connection_string() -> str:
    return os.environ.get("AZURE_STORAGE_CONNECTION_STRING", "").strip()


def configured() -> bool:
    return bool(_connection_string())


@lru_cache(maxsize=8)
def _table(name: str):
    from azure.data.tables import TableServiceClient

    service = TableServiceClient.from_connection_string(_connection_string())
    service.create_table_if_not_exists(name)
    return service.get_table_client(name)


def _safe_key(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()


def _escape_filter(value: str) -> str:
    return value.replace("'", "''")


def get_user_by_email(email: str):
    if not configured() or not email:
        return None, None
    try:
        entity = _table("netmaskusers").get_entity("users", _safe_key(email))
        data = dict(entity)
        return data, data["email"]
    except Exception:  # Azure returns ResourceNotFoundError for an unknown account.
        return None, None


def get_user_by_username(username: str):
    if not configured() or not username:
        return None, None
    try:
        query = f"PartitionKey eq 'users' and username_normalized eq '{_escape_filter(username.lower())}'"
        entity = next(iter(_table("netmaskusers").query_entities(query, results_per_page=1)), None)
        if not entity:
            return None, None
        data = dict(entity)
        return data, data["email"]
    except Exception:
        return None, None


def create_user(*, username: str, email: str, fullname: str, password_hash: str) -> str:
    from azure.core.exceptions import ResourceExistsError

    entity = {
        "PartitionKey": "users",
        "RowKey": _safe_key(email),
        "email": email,
        "username": username,
        "username_normalized": username.lower(),
        "fullname": fullname,
        "password_hash": password_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        _table("netmaskusers").create_entity(entity)
    except ResourceExistsError as exc:
        raise ValueError("Email already registered") from exc
    return email


def save_incident(incident: dict[str, Any]) -> None:
    if not configured():
        return
    entity = {
        "PartitionKey": "incidents",
        "RowKey": str(incident["incident_id"]),
        "classification": str(incident.get("classification", "Unknown")),
        "source_ip": str(incident.get("source_ip", "unknown")),
        "destination_ip": str(incident.get("destination_ip", "unknown")),
        "protocol": str(incident.get("protocol", "unknown")),
        "risk_level": str(incident.get("risk_level", "unknown")),
        "status": str(incident.get("status", "new")),
        "event_count": int(incident.get("event_count", 1)),
        "first_seen": str(incident.get("first_seen", "")),
        "last_seen": str(incident.get("last_seen", "")),
        "max_attack_probability": float(incident.get("max_attack_probability", 0.0)),
        "latest_flow_id": str(incident.get("latest_flow_id", "")),
        "sensor_id": str(incident.get("sensor_id", "unknown")),
    }
    _table("netmaskincidents").upsert_entity(entity)


def _incident_payload(entity: dict[str, Any]) -> dict[str, Any]:
    return {
        "incident_id": entity["RowKey"],
        "classification": entity.get("classification", "Unknown"),
        "source_ip": entity.get("source_ip", "unknown"),
        "destination_ip": entity.get("destination_ip", "unknown"),
        "protocol": entity.get("protocol", "unknown"),
        "risk_level": entity.get("risk_level", "unknown"),
        "status": entity.get("status", "new"),
        "event_count": int(entity.get("event_count", 1)),
        "first_seen": entity.get("first_seen", ""),
        "last_seen": entity.get("last_seen", ""),
        "max_attack_probability": float(entity.get("max_attack_probability", 0.0)),
        "latest_flow_id": entity.get("latest_flow_id") or None,
        "sensor_id": entity.get("sensor_id", "unknown"),
    }


def list_incidents(limit: int = 100) -> list[dict[str, Any]]:
    if not configured():
        return []
    entities = _table("netmaskincidents").query_entities("PartitionKey eq 'incidents'")
    values = [_incident_payload(dict(entity)) for entity in entities]
    values.sort(key=lambda item: item.get("last_seen", ""), reverse=True)
    return values[:limit]


def get_incident(incident_id: str) -> dict[str, Any] | None:
    if not configured():
        return None
    try:
        entity = _table("netmaskincidents").get_entity("incidents", incident_id)
        return _incident_payload(dict(entity))
    except Exception:
        return None


def acknowledge_incident(incident_id: str) -> dict[str, Any] | None:
    incident = get_incident(incident_id)
    if not incident:
        return None
    incident["status"] = "acknowledged"
    save_incident(incident)
    return incident


def create_share(incident: dict[str, Any], *, expires_hours: int = 168) -> tuple[str, str]:
    if not configured():
        raise RuntimeError("Azure report storage is not configured")
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_hours)
    _table("netmaskshares").create_entity({
        "PartitionKey": "shares",
        "RowKey": _safe_key(token),
        "incident_json": json.dumps(incident, separators=(",", ":")),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at.isoformat(),
    })
    return token, expires_at.isoformat()


def resolve_share(token: str) -> dict[str, Any] | None:
    if not configured() or not token:
        return None
    try:
        entity = _table("netmaskshares").get_entity("shares", _safe_key(token))
        expires_at = datetime.fromisoformat(str(entity["expires_at"]))
        if expires_at <= datetime.now(timezone.utc):
            return None
        incident = json.loads(str(entity["incident_json"]))
        incident["share_expires_at"] = str(entity["expires_at"])
        return incident
    except Exception:
        return None
