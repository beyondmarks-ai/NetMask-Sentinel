"""Environment-backed application configuration with safe defaults."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    value = os.environ.get(name)
    return int(value) if value else default


def _origins(value: str | None) -> tuple[str, ...]:
    raw = value or "http://127.0.0.1:5000,http://localhost:5000"
    return tuple(item.strip() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    environment: str
    secret_key: str
    debug: bool
    guest_access: bool
    debug_routes: bool
    capture_enabled: bool
    capture_interface: str | None
    capture_filter: str
    flow_timeout_seconds: int
    incident_window_seconds: int
    cors_origins: tuple[str, ...]

    @property
    def production(self) -> bool:
        return self.environment == "production"

    @classmethod
    def from_env(cls) -> "Settings":
        environment = os.environ.get("NETMASK_ENV", "development").strip().lower()
        production = environment == "production"
        secret_key = os.environ.get("FLASK_SECRET_KEY", "")
        if production and len(secret_key) < 32:
            raise RuntimeError("FLASK_SECRET_KEY must contain at least 32 characters in production")
        if not secret_key:
            secret_key = secrets.token_urlsafe(32)

        settings = cls(
            environment=environment,
            secret_key=secret_key,
            debug=_bool("FLASK_DEBUG", False) and not production,
            guest_access=_bool("ENABLE_GUEST_ACCESS", not production),
            debug_routes=_bool("ENABLE_DEBUG_ROUTES", not production),
            capture_enabled=_bool("CAPTURE_ENABLED", True),
            capture_interface=os.environ.get("CAPTURE_INTERFACE") or None,
            capture_filter=os.environ.get("CAPTURE_FILTER", "ip and (tcp or udp)"),
            flow_timeout_seconds=_int("FLOW_TIMEOUT_SECONDS", 120),
            incident_window_seconds=_int("INCIDENT_WINDOW_SECONDS", 120),
            cors_origins=_origins(os.environ.get("CORS_ORIGINS")),
        )
        if settings.flow_timeout_seconds <= 0 or settings.incident_window_seconds <= 0:
            raise RuntimeError("Timeout settings must be positive")
        if production and (settings.guest_access or settings.debug_routes):
            raise RuntimeError("Guest access and debug routes must be disabled in production")
        return settings