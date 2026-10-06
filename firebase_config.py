"""
Firestore + auth helpers. If `firebase-adminsdk.json` is not present, DB-backed
auth is disabled but the app still starts (static routes work; login needs Firebase).
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

import firebase_admin
from firebase_admin import credentials, firestore
from firebase_admin.firestore import SERVER_TIMESTAMP
from werkzeug.security import check_password_hash, generate_password_hash

_root = Path(__file__).resolve().parent
_credential_path = Path(os.environ.get("FIREBASE_CREDENTIALS", str(_root / "firebase-adminsdk.json")))

firestore_db = None
_local_auth_path = _root / "runtime" / "accounts.sqlite3"

try:
    if not firebase_admin._apps:
        if _credential_path.is_file():
            firebase_admin.initialize_app(credentials.Certificate(str(_credential_path)))
        else:
            print(f"Firebase: credentials file not found at {_credential_path}")

    # Even when an app already exists (e.g. Flask debug reloader), always attach client.
    if firebase_admin._apps:
        firestore_db = firestore.client()
except Exception as e:  # noqa: BLE001
    print(f"Firebase: could not initialize from {_credential_path}: {e}")


def hash_password(password: str) -> str | None:
    if not password:
        return None
    return generate_password_hash(password, method="scrypt")


def verify_password(stored_hash: str | None, password: str) -> bool:
    if not stored_hash or not password:
        return False
    return check_password_hash(stored_hash, password)


def _local_connection() -> sqlite3.Connection:
    """Open the local development account store when Firebase is not configured."""
    _local_auth_path.parent.mkdir(exist_ok=True)
    connection = sqlite3.connect(_local_auth_path)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY COLLATE NOCASE,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        fullname TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
        )"""
    )
    return connection


def get_user_by_email(email: str):
    if not email:
        return None, None
    try:
        if firestore_db:
            document = firestore_db.collection("users").document(email).get()
            return (document.to_dict(), document.id) if document.exists else (None, None)
        with _local_connection() as connection:
            row = connection.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        return (dict(row), row["email"]) if row else (None, None)
    except Exception:  # noqa: BLE001
        return None, None


def get_user_by_username(username: str):
    if not username:
        return None, None
    try:
        if firestore_db:
            snap = list(
                firestore_db.collection("users").where("username", "==", username).limit(1).stream()
            )
            if not snap:
                return None, None
            doc = snap[0]
            return doc.to_dict(), doc.id
        with _local_connection() as connection:
            row = connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return (dict(row), row["email"]) if row else (None, None)
    except Exception:  # noqa: BLE001
        return None, None


def create_user(*, username: str, email: str, fullname: str, password_hash: str) -> str:
    """Create an account in Firestore when available, otherwise in local SQLite."""
    if firestore_db:
        firestore_db.collection("users").document(email).set({
            "username": username,
            "email": email,
            "fullname": fullname,
            "password_hash": password_hash,
            "created_at": SERVER_TIMESTAMP,
            "last_active": SERVER_TIMESTAMP,
        })
        return email
    with _local_connection() as connection:
        connection.execute(
            "INSERT INTO users (email, username, fullname, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            (email, username, fullname, password_hash, datetime.now(timezone.utc).isoformat()),
        )
    return email


def create_user_session(user_id, device_info=None):
    if not firestore_db:
        return f"dev-{uuid.uuid4().hex[:12]}"
    try:
        sid = uuid.uuid4().hex
        data = {
            "user_id": user_id,
            "created_at": SERVER_TIMESTAMP,
            "last_active": SERVER_TIMESTAMP,
        }
        if device_info:
            data["device"] = device_info
        firestore_db.collection("sessions").document(sid).set(data)
        return sid
    except Exception as e:  # noqa: BLE001
        print(f"create_user_session: {e}")
        return None


def update_global_stats():
    if not firestore_db:
        return
    try:
        ref = firestore_db.collection("app_stats").document("global")
        ref.set(
            {
                "last_event": SERVER_TIMESTAMP,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
            merge=True,
        )
    except Exception as e:  # noqa: BLE001
        print(f"update_global_stats: {e}")


def _build_structured_flow_doc(*, user_id, session_id, flow_data):
    classification = flow_data.get("Classification")
    risk_level = flow_data.get("risk_level", "unknown")
    probability = flow_data.get("Probability")
    try:
        probability = float(probability) if probability is not None else None
    except Exception:  # noqa: BLE001
        probability = None

    return {
        "user_id": user_id,
        "session_id": session_id,
        "flow_id": flow_data.get("FlowID"),
        "network": {
            "src_ip": flow_data.get("Src"),
            "src_port": flow_data.get("SrcPort"),
            "dst_ip": flow_data.get("Dest"),
            "dst_port": flow_data.get("DestPort"),
            "protocol": flow_data.get("Protocol"),
        },
        "timing": {
            "flow_start": flow_data.get("FlowStartTime"),
            "flow_end": flow_data.get("FlowLastSeen"),
            "duration": flow_data.get("FlowDuration"),
        },
        "app": {
            "name": flow_data.get("PName"),
            "pid": flow_data.get("PID"),
        },
        "detection": {
            "classification": classification,
            "is_attack": str(classification).lower() != "benign",
            "probability": probability,
            "risk": {
                "level": risk_level,
            },
        },
        "created_at": SERVER_TIMESTAMP,
        # Keep full payload for audit/debug and model traceability.
        "raw": flow_data,
    }


def save_captured_flow(*, user_id, session_id, flow_data):
    if not firestore_db:
        return f"local-captured-{user_id or 'anon'}"
    try:
        doc = firestore_db.collection("captured_flows").document()
        payload = _build_structured_flow_doc(
            user_id=user_id,
            session_id=session_id,
            flow_data=flow_data,
        )
        doc.set(payload)
        return doc.id
    except Exception as e:  # noqa: BLE001
        print(f"save_captured_flow: {e}")
        return None


def save_malicious_flow(*, user_id, session_id, flow_data):
    if not firestore_db:
        return f"local-{user_id or 'anon'}"
    try:
        doc = firestore_db.collection("malicious_flows").document()
        payload = _build_structured_flow_doc(
            user_id=user_id,
            session_id=session_id,
            flow_data=flow_data,
        )
        # Explicit convenience fields used by dashboard queries.
        payload["risk"] = payload["detection"]["risk"]
        payload["classification"] = payload["detection"]["classification"]
        doc.set(payload)
        return doc.id
    except Exception as e:  # noqa: BLE001
        print(f"save_malicious_flow: {e}")
        return None


def increment_high_risk_count(session_id, risk_level):
    if not firestore_db or not session_id:
        return
    try:
        ref = firestore_db.collection("sessions").document(session_id)
        field = f"risk_count_{risk_level}"
        ref.set({field: firestore.Increment(1), "last_risk": risk_level}, merge=True)
    except Exception as e:  # noqa: BLE001
        print(f"increment_high_risk_count: {e}")
