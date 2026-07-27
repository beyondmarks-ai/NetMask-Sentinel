"""
Firestore + auth helpers. If `firebase-adminsdk.json` is not present, DB-backed
auth is disabled but the app still starts (static routes work; login needs Firebase).
"""
from __future__ import annotations

import os
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


def get_user_by_username(username: str):
    if not firestore_db or not username:
        return None, None
    try:
        snap = list(
            firestore_db.collection("users").where("username", "==", username).limit(1).stream()
        )
        if not snap:
            return None, None
        doc = snap[0]
        return doc.to_dict(), doc.id
    except Exception:  # noqa: BLE001
        return None, None


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
