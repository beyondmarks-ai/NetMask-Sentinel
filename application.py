from datetime import datetime
from pathlib import Path
from threading import Lock
import atexit
import csv
import json
import logging
import os
import pickle
import hmac
import ipaddress
import secrets
import time
import traceback

import numpy as np
import pandas as pd
import plotly
import plotly.graph_objs
from firebase_admin.firestore import SERVER_TIMESTAMP
from flask import Flask, flash, has_request_context, jsonify, redirect, render_template, request, session, url_for
from flask_cors import CORS
from flask_socketio import SocketIO

from firebase_config import (
    firestore_db, create_user_session, update_global_stats,
    hash_password, verify_password, get_user_by_username, save_captured_flow,
    save_malicious_flow, increment_high_risk_count,
)
from netmask.config import Settings
from netmask.detection import DetectionEngine
from netmask.features import FEATURE_NAMES, split_flow_record
from netmask.incidents import IncidentManager
from netmask.sensor import CaptureService
from netmask.telemetry import RuntimeMetrics

settings = Settings.from_env()


def is_local_request():
    try:
        return ipaddress.ip_address(request.remote_addr or "").is_loopback
    except ValueError:
        return False
app = Flask(__name__)
app.config.update(
    SECRET_KEY=settings.secret_key,
    DEBUG=settings.debug,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=settings.production,
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)
@app.before_request
def protect_state_changes():
    """Require a session-bound token for state-changing browser requests."""
    session.setdefault("csrf_token", secrets.token_urlsafe(32))
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return None
    if request.endpoint == "debug_mock_flow" and settings.debug_routes and is_local_request():
        return None
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    expected = session.get("csrf_token", "")
    if not supplied or not hmac.compare_digest(str(supplied), str(expected)):
        return jsonify({"error": "csrf_validation_failed"}), 400
    return None


@app.context_processor
def inject_security_context():
    return {"csrf_token": session.get("csrf_token", "")}

CORS(app, origins=list(settings.cors_origins), supports_credentials=True)

socketio = SocketIO(
    app,
    async_mode="threading",
    logger=False,
    engineio_logger=False,
    cors_allowed_origins=list(settings.cors_origins),
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("netmask")
runtime_dir = Path("runtime")
runtime_dir.mkdir(exist_ok=True)
flow_state_lock = Lock()
cols = ['FlowID',
'FlowDuration',
'BwdPacketLenMax',
'BwdPacketLenMin',
'BwdPacketLenMean',
'BwdPacketLenStd',
'FlowIATMean',
'FlowIATStd',
'FlowIATMax',
'FlowIATMin',
'FwdIATTotal',
'FwdIATMean',
'FwdIATStd',
'FwdIATMax',
'FwdIATMin',
'BwdIATTotal',
'BwdIATMean',
'BwdIATStd',
'BwdIATMax',
'BwdIATMin',
'FwdPSHFlags',
'FwdPackets_s',
'MaxPacketLen',
'PacketLenMean',
'PacketLenStd',
'PacketLenVar',
'FINFlagCount',
'SYNFlagCount',
'PSHFlagCount',
'ACKFlagCount',
'URGFlagCount',
'AvgPacketSize',
'AvgBwdSegmentSize',
'InitWinBytesFwd',
'InitWinBytesBwd',
'ActiveMin',
'IdleMean',
'IdleStd',
'IdleMax',
'IdleMin',
'Src',
'SrcPort',
'Dest',
'DestPort',
'Protocol',
'FlowStartTime',
'FlowLastSeen',
'PName',
'PID',
'Classification',
'Probability',
'Risk']

ae_features = np.array(['FlowDuration',
'BwdPacketLengthMax',
'BwdPacketLengthMin',
'BwdPacketLengthMean',
'BwdPacketLengthStd',
'FlowIATMean',
'FlowIATStd',
'FlowIATMax',
'FlowIATMin',
'FwdIATTotal',
'FwdIATMean',
'FwdIATStd',
'FwdIATMax',
'FwdIATMin',
'BwdIATTotal',
'BwdIATMean',
'BwdIATStd',
'BwdIATMax',
'BwdIATMin',
'FwdPSHFlags',
'FwdPackets/s',
'PacketLengthMax',
'PacketLengthMean',
'PacketLengthStd',
'PacketLengthVariance',
'FINFlagCount',
'SYNFlagCount',
'PSHFlagCount',
'ACKFlagCount',
'URGFlagCount',
'AveragePacketSize',
'BwdSegmentSizeAvg',
'FWDInitWinBytes',
'BwdInitWinBytes',
'ActiveMin',
'IdleMean',
'IdleStd',
'IdleMax',
'IdleMin'])

flow_count = 0
flow_df = pd.DataFrame(columns=cols)

src_ip_dict = {}

# Load and validate the production classifier once at startup.
try:
    with open("models/model.pkl", "rb") as model_file:
        classifier = pickle.load(model_file)
    detection_engine = DetectionEngine(
        classifier,
        model_path="models/model.pkl",
        model_version="legacy-rf-1",
    )
    detection_engine.write_metadata("runtime/model_metadata.json")
    predict_fn_rf = lambda values: classifier.predict_proba(values).astype(float)
except Exception as exc:
    logger.exception("Model startup validation failed")
    raise RuntimeError(f"Unable to initialize detection model: {exc}") from exc

_explanation_assets = None
_explanation_assets_lock = Lock()


def load_explanation_assets():
    """Load heavyweight optional explanation models only when requested."""
    global _explanation_assets
    with _explanation_assets_lock:
        if _explanation_assets is None:
            import dill
            import joblib
            from tensorflow import keras

            scaler = joblib.load("models/preprocess_pipeline_AE_39ft.save")
            autoencoder = keras.models.load_model(
                "models/autoencoder_39ft.hdf5", compile=False
            )
            with open("models/explainer", "rb") as explainer_file:
                lime_explainer = dill.load(explainer_file)
            _explanation_assets = (scaler, autoencoder, lime_explainer)
    return _explanation_assets

runtime_metrics = RuntimeMetrics()
incident_manager = IncidentManager(window_seconds=settings.incident_window_seconds)
def _append_runtime_csv(path: Path, fieldnames: list[str], row: dict[str, object]) -> None:
    """Append structured runtime evidence without modifying tracked fixture files."""
    with flow_state_lock:
        write_header = not path.exists() or path.stat().st_size == 0
        with path.open("a", newline="", encoding="utf-8") as destination:
            writer = csv.DictWriter(destination, fieldnames=fieldnames)
            if write_header:
                writer.writeheader()
            writer.writerow(row)


def _firestore_safe(value):
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, (datetime,)):
        return value.isoformat()
    if pd.isna(value):
        return None
    return value


def classify(record):
    """Validate, classify, persist, correlate, and broadcast one completed flow."""
    global flow_count
    try:
        features, metadata = split_flow_record(record)
        detection = detection_engine.detect(features)
        runtime_metrics.increment("classified_flows_total")
        runtime_metrics.increment(f"classification_{detection.classification}")
        runtime_metrics.increment(f"risk_{detection.risk_level}")
        runtime_metrics.observe_inference(detection.inference_ms)

        with flow_state_lock:
            flow_count += 1
            assigned_flow_id = flow_count
            source_ip = str(metadata["Src"])
            src_ip_dict[source_ip] = src_ip_dict.get(source_ip, 0) + 1

        risk_display = detection.risk_level.replace("_", " ").title()
        metadata_values = [str(metadata[name]) for name in (
            "Src", "SrcPort", "Dest", "DestPort", "Protocol",
            "FlowStartTime", "FlowLastSeen", "PName", "PID",
        )]
        table_row = [
            assigned_flow_id,
            *metadata_values,
            detection.classification,
            detection.confidence,
            risk_display,
        ]
        dataframe_row = [
            assigned_flow_id,
            *list(record),
            detection.classification,
            detection.confidence,
            risk_display,
        ]
        flow_data = dict(zip(cols, dataframe_row, strict=True))
        flow_data["risk_level"] = detection.risk_level
        flow_data["attack_probability"] = detection.attack_probability
        flow_data["model_version"] = detection.model_version

        with flow_state_lock:
            flow_df.loc[len(flow_df)] = dataframe_row

        _append_runtime_csv(
            runtime_dir / "captured_flows.csv",
            list(flow_data.keys()),
            {key: _firestore_safe(value) for key, value in flow_data.items()},
        )
        _append_runtime_csv(
            runtime_dir / "model_inputs.csv",
            list(FEATURE_NAMES),
            dict(zip(FEATURE_NAMES, features.tolist(), strict=True)),
        )

        incident = None
        if detection.should_alert:
            runtime_metrics.increment("alerts_total")
            incident = incident_manager.record(
                classification=detection.classification,
                source_ip=str(metadata["Src"]),
                destination_ip=str(metadata["Dest"]),
                protocol=str(metadata["Protocol"]),
                risk_level=detection.risk_level,
                attack_probability=detection.attack_probability,
                flow_id=assigned_flow_id,
            )

        if firestore_db:
            user_id = session.get("user_id", "sensor") if has_request_context() else "sensor"
            session_id = session.get("session_id", "capture-service") if has_request_context() else "capture-service"
            clean_flow_data = {
                key: _firestore_safe(value) for key, value in flow_data.items()
            }
            save_captured_flow(
                user_id=user_id,
                session_id=session_id,
                flow_data=clean_flow_data,
            )
            if detection.should_alert:
                save_malicious_flow(
                    user_id=user_id,
                    session_id=session_id,
                    flow_data=clean_flow_data,
                )
                increment_high_risk_count(session_id, detection.risk_level)
            if detection.should_alert or assigned_flow_id % 10 == 0:
                update_global_stats()

        with flow_state_lock:
            ip_data = [
                {"SourceIP": address, "count": count}
                for address, count in src_ip_dict.items()
            ]

        socketio.emit(
            "newresult",
            {
                "result": table_row,
                "ips": ip_data,
                "risk_level": detection.risk_level,
                "classification": detection.classification,
                "detection": detection.to_dict(),
                "incident": incident.to_dict() if incident else None,
            },
            namespace="/test",
        )
        return dataframe_row
    except Exception as exc:
        runtime_metrics.error(str(exc))
        logger.exception("Flow classification failed")
        return None


capture_service = CaptureService(
    classify,
    interface=settings.capture_interface,
    packet_filter=settings.capture_filter,
    flow_timeout_seconds=settings.flow_timeout_seconds,
)

@app.route('/test-firebase', methods=['GET'])
def test_firebase():
    if not settings.debug_routes:
        return jsonify({"error": "not_found"}), 404
    try:
        if not firestore_db:
            return jsonify({"status": "error", "message": "Firestore not initialized"}), 500

        # Create document reference first
        doc_ref = firestore_db.collection("connection_tests").document()
        
        # Prepare data WITHOUT SERVER_TIMESTAMP for the response
        test_data = {
            "test": "NetMask Sentinel Connection Test",
            "status": "success",
            "document_id": doc_ref.id
        }

        # Create separate data for Firestore WITH timestamp
        firestore_data = {
            **test_data,
            "timestamp": SERVER_TIMESTAMP  # Only for Firestore
        }

        # Write to Firestore
        doc_ref.set(firestore_data)
        
        # Return response without the timestamp
        return jsonify({
            "status": "success",
            "data": test_data
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e),
            "solution": "Check firebase-adminsdk.json and Firestore rules"
        }), 500

@app.get('/health/live')
def health_live():
    return jsonify({"status": "alive", "service": "netmask"})


@app.get('/health/ready')
def health_ready():
    capture = capture_service.health()
    capture_ready = not settings.capture_enabled or (
        capture["running"] and not capture["last_error"]
    )
    status = "ready" if capture_ready else "degraded"
    return jsonify({
        "status": status,
        "model": {
            "ready": True,
            "version": detection_engine.model_version,
            "classes": list(detection_engine.classes),
        },
        "capture": capture,
        "firestore": {"configured": firestore_db is not None, "required": False},
    }), 200 if capture_ready else 503


@app.get('/api/metrics')
def api_metrics():
    if not session.get('logged_in'):
        return jsonify({"error": "authentication_required"}), 401
    return jsonify({
        "runtime": runtime_metrics.snapshot(),
        "capture": capture_service.health(),
        "incidents": incident_manager.summary(),
    })


@app.get('/api/model')
def api_model():
    if not session.get('logged_in'):
        return jsonify({"error": "authentication_required"}), 401
    return jsonify(detection_engine.metadata())


@app.get('/api/incidents')
def api_incidents():
    if not session.get('logged_in'):
        return jsonify({"error": "authentication_required"}), 401
    limit = min(max(request.args.get('limit', 100, type=int), 1), 500)
    return jsonify({
        "items": incident_manager.list(limit=limit, status=request.args.get('status')),
        "summary": incident_manager.summary(),
    })


@app.post('/api/incidents/<incident_id>/acknowledge')
def acknowledge_incident(incident_id):
    if not session.get('logged_in'):
        return jsonify({"error": "authentication_required"}), 401
    incident = incident_manager.acknowledge(incident_id)
    if not incident:
        return jsonify({"error": "incident_not_found"}), 404
    return jsonify({"success": True, "incident": incident})


# Route for the landing page (default page)
@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/guest')
def guest_access():
    """Allow local evaluation when Firebase authentication is unavailable."""
    if not settings.guest_access or not is_local_request():
        return redirect(url_for('landing'))

    session.clear()
    session['logged_in'] = True
    session['username'] = 'Guest'
    session['user_id'] = 'guest-local'
    session['email'] = ''
    session['fullname'] = 'Guest User'
    session['session_id'] = create_user_session('guest-local')
    session['is_guest'] = True
    return redirect(url_for('capture'))


# Route for handling login form submission
@app.route('/login', methods=['POST'])
def login():
    if not firestore_db:
        message = "Cloud authentication is unavailable. Use guest access in development."
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"success": False, "message": message}), 503
        flash(message)
        return redirect(url_for('landing'))
    try:
        # Get username and password from form or JSON
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')

        # Add debug logging to track flow
        print(f"Login attempt for username: {username}")
        
        # Check if request is AJAX (XHR)
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        
        # Basic validation
        if not username or not password:
            error_msg = "Username and password are required"
            print(f"Login error: {error_msg}")
            if is_ajax:
                return jsonify({"success": False, "message": error_msg}), 400
            flash(error_msg)
            return redirect(url_for('landing'))
            
        # Try multiple lookup strategies
        user_data = None
        user_id = None
        
        # Strategy 1: Check if the input is an email (has @)
        if '@' in username:
            print("Email format detected, trying direct document lookup...")
            user_ref = firestore_db.collection('users').document(username)
            user_doc = user_ref.get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
                user_id = username
                print(f"Found user via direct email lookup: {user_id}")
        
        # Strategy 2: Use the get_user_by_username function
        if not user_data:
            print("Trying username lookup via query...")
            user_data, user_id = get_user_by_username(username)
            if user_data:
                print(f"Found user via username query: {user_id}")
        
        # Strategy 3: Try with @example.com appended if no @ in username
        if not user_data and '@' not in username:
            print("Trying email with default domain...")
            email_to_try = f"{username}@example.com"
            user_ref = firestore_db.collection('users').document(email_to_try)
            user_doc = user_ref.get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
                user_id = email_to_try
                print(f"Found user via default domain email: {user_id}")
        
        # Debug output for troubleshooting
        if user_data:
            print(f"User data retrieved. Has password hash: {'password_hash' in user_data}")
        else:
            print("No user data found with provided username/email")
            
        # Verify user exists and password matches
        if not user_data:
            error_msg = "User not found"
            print(f"Login error: {error_msg}")
            if is_ajax:
                return jsonify({"success": False, "message": "Invalid username or password"}), 401
            flash("Invalid username or password")
            return redirect(url_for('landing'))
            
        # Check if password hash exists
        if 'password_hash' not in user_data:
            error_msg = "Password hash not found in user data"
            print(f"Login error: {error_msg}")
            if is_ajax:
                return jsonify({"success": False, "message": "Account setup incomplete. Please contact admin."}), 401
            flash("Account setup incomplete. Please contact admin.")
            return redirect(url_for('landing'))
            
        # Verify password
        if not verify_password(user_data.get('password_hash'), password):
            error_msg = "Password verification failed"
            print(f"Login error: {error_msg}")
            if is_ajax:
                return jsonify({"success": False, "message": "Invalid username or password"}), 401
            flash("Invalid username or password")
            return redirect(url_for('landing'))
            
        # Authentication successful
        print(f"User {username} authenticated successfully")
        
        # User authenticated, set up session
        session['logged_in'] = True
        session['username'] = user_data.get('username', username)
        session['user_id'] = user_id
        session['email'] = user_data.get('email', user_id if '@' in user_id else f"{user_id}@example.com")
        session['fullname'] = user_data.get('fullname', '')
        session['new_session'] = True

        # Get device info
        user_agent = request.user_agent
        device_info = {
            'os': user_agent.platform if user_agent else 'Unknown',
            'browser': user_agent.browser if user_agent else 'Unknown',
            'ip_address': request.remote_addr or '0.0.0.0'
        }
        
        # Create Firestore session
        session_id = create_user_session(user_id, device_info)
        if session_id:
            session['session_id'] = session_id
            print(f"Created Firestore session: {session_id}")
            
            # Initialize global stats
            update_global_stats()
        else:
            session['session_id'] = 'default_session'
            print("Using default session ID")
        
        # Return appropriate response based on request format
        if is_ajax:
            return jsonify({"success": True, "redirect": url_for('capture')})
        return redirect(url_for('capture'))
        
    except Exception as e:
        print(f"Login error: {e}")
        traceback.print_exc()
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if is_ajax:
            return jsonify({"success": False, "message": "Login failed. Please try again."}), 500
        flash('Login failed. Please try again.')
        return redirect(url_for('landing'))
    

# Route for the capture page (index.html)
@app.route('/capture')
def capture():
    # Check if the user is logged in
    if not session.get('logged_in'):
        return redirect(url_for('landing'))  # Redirect to landing page if not logged in
    return render_template('index.html')

# Route for the signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    if not firestore_db:
        message = "Cloud account creation is unavailable because Firebase is not configured."
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"success": False, "message": message}), 503
        flash(message)
        return render_template('signup.html'), 503
    
    # Check if the request is AJAX
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    try:
        # Get form data
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        email = request.form.get('email', '').strip()
        fullname = request.form.get('fullname', '').strip()
        
        # Validation errors dictionary
        errors = {}
        
        # Validate input
        if not username:
            errors['username'] = 'Username is required'
        if not password:
            errors['password'] = 'Password is required'
        if not email:
            errors['email'] = 'Email is required'
        
        # Handle validation errors
        if errors:
            if is_ajax:
                return jsonify({"success": False, "errors": errors}), 400
            for field, message in errors.items():
                flash(message)
            return render_template('signup.html')
        
        # Check if email contains @ - if not, add default domain
        if '@' not in email:
            email = f"{email}@example.com"
        
        # Check if username already exists
        existing_user, _ = get_user_by_username(username)
        if existing_user:
            if is_ajax:
                return jsonify({"success": False, "errors": {"username": "Username already exists"}}), 400
            flash('Username already exists')
            return render_template('signup.html')
        
        # Check if email already exists as a document ID
        user_ref = firestore_db.collection('users').document(email)
        if user_ref.get().exists:
            if is_ajax:
                return jsonify({"success": False, "errors": {"email": "Email already registered"}}), 400
            flash('Email already registered')
            return render_template('signup.html')
        
        # Hash password
        password_hash = hash_password(password)
        if not password_hash:
            if is_ajax:
                return jsonify({"success": False, "message": "Error creating account. Please try again."}), 500
            flash('Error creating account. Please try again.')
            return render_template('signup.html')
        
        # Create user document
        user_data = {
            'username': username,
            'email': email,
            'fullname': fullname if fullname else username,
            'password_hash': password_hash,
            'created_at': SERVER_TIMESTAMP,
            'last_active': SERVER_TIMESTAMP
        }
        
        # Save to Firestore
        user_ref.set(user_data)
        
        # Log success
        print(f"User created: {email} with username: {username}")
        
        # Automatically log in the user
        session['logged_in'] = True
        session['username'] = username
        session['user_id'] = email
        session['email'] = email
        session['fullname'] = fullname if fullname else username
        session['new_session'] = True
        
        # Create session
        session_id = create_user_session(email)
        if session_id:
            session['session_id'] = session_id
        
        # Return appropriate response
        if is_ajax:
            return jsonify({"success": True, "redirect": url_for('capture')})
        
        flash('Account created successfully!')
        return redirect(url_for('capture'))
        
    except Exception as e:
        print(f"Signup error: {e}")
        traceback.print_exc()
        
        if is_ajax:
            return jsonify({"success": False, "message": "Error creating account. Please try again."}), 500
        
        flash('Error creating account. Please try again.')
        return render_template('signup.html')

# Route for the detail page (Detail.html)
@app.route('/detail')
def detail():
    if not session.get('logged_in'):
        return redirect(url_for('landing'))
    try:
        ae_scaler, ae_model, explainer = load_explanation_assets()
        flow_id = request.args.get('flow_id', default=-1, type=int)
        flow = flow_df.loc[flow_df['FlowID'] == flow_id]
        
        if flow.empty:
            return "Flow not found", 404
            
        X = [flow.values[0,1:40]]
        choosen_instance = X
        proba_score = list(predict_fn_rf(choosen_instance))
        risk_proba = sum(proba_score[0][1:])
        
        if risk_proba > 0.8:
            risk = "Risk: <p style=\"color:red;\">Very High</p>"
        elif risk_proba > 0.6:
            risk = "Risk: <p style=\"color:orangered;\">High</p>"
        elif risk_proba > 0.4:
            risk = "Risk: <p style=\"color:orange;\">Medium</p>"
        elif risk_proba > 0.2:
            risk = "Risk: <p style=\"color:green;\">Low</p>"
        else:
            risk = "Risk: <p style=\"color:limegreen;\">Minimal</p>"
            
        exp = explainer.explain_instance(choosen_instance[0], predict_fn_rf, num_features=6, top_labels=1)

        X_transformed = ae_scaler.transform(X)
        reconstruct = ae_model.predict(X_transformed)
        err = reconstruct - X_transformed
        abs_err = np.absolute(err)
        
        ind_n_abs_largest = np.argpartition(abs_err, -5)[-5:]
        col_n_largest = ae_features[ind_n_abs_largest]
        err_n_largest = err[0][ind_n_abs_largest]
        
        plot_div = plotly.offline.plot({
            "data": [
                plotly.graph_objs.Bar(x=col_n_largest[0].tolist(), y=err_n_largest[0].tolist())
            ]
        }, include_plotlyjs=False, output_type='div')

        return render_template(
            'detail.html',
            tables=[flow.reset_index(drop=True).transpose().to_html(classes='data')],
            exp=exp.as_html(),
            ae_plot=plot_div,
            risk=risk
        )
    except Exception as e:
        print(f"Error in flow_detail: {str(e)}")
        traceback.print_exc()
        return "Error processing request", 500

# Route for the profile page
@app.route('/profile')
def profile():
    if not session.get('logged_in'):
        return redirect(url_for('landing'))
    
    # Fetch user details from the session or database
    username = session.get('username')
    email = session.get('email')  # Ensure email is stored in the session during login/signup
    fullname = session.get('fullname')  # Ensure fullname is stored in the session during signup
    
    return render_template('profile.html', username=username, email=email, fullname=fullname)

@app.route('/clear-local-flows')
def clear_local_flows():
    if not session.get('logged_in'):
        return jsonify({"status": "error", "message": "Not authorized"}), 401
    return jsonify({"status": "success", "message": "Local flows cleared"})

# Add this route to your application.py file
@app.route('/debug_auth', methods=['GET'])
def debug_auth():
    """Debug route for authentication issues (remove in production)"""
    if not settings.debug_routes:
        return jsonify({'error': 'not_found'}), 404

    try:
        # Check if a username is provided
        test_username = request.args.get('username')
        if not test_username:
            return jsonify({
                "status": "Need username parameter",
                "usage": "/debug_auth?username=your_username"
            })
        
        # Try to find the user
        user_data, user_id = get_user_by_username(test_username)
        
        # If not found by username, try email
        if not user_data and '@' not in test_username:
            email_to_try = f"{test_username}@example.com"
            user_ref = firestore_db.collection('users').document(email_to_try)
            user_doc = user_ref.get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
                user_id = email_to_try
        
        # Prepare response
        if not user_data:
            return jsonify({
                "status": "User not found",
                "username": test_username,
                "lookups_tried": [
                    f"Username match: {test_username}",
                    f"Email direct: {test_username if '@' in test_username else f'{test_username}@example.com'}"
                ]
            })
        
        # Return user info (redact sensitive data)
        safe_data = {
            "status": "User found",
            "username": user_data.get('username'),
            "user_id": user_id,
            "email": user_data.get('email'),
            "has_password_hash": 'password_hash' in user_data,
            "password_hash_length": len(user_data.get('password_hash', '')) if 'password_hash' in user_data else 0,
            "created_at": user_data.get('created_at').strftime('%Y-%m-%d %H:%M:%S') if user_data.get('created_at') else None,
            "last_active": user_data.get('last_active').strftime('%Y-%m-%d %H:%M:%S') if user_data.get('last_active') else None
        }
        
        return jsonify(safe_data)
    except Exception as e:
        return jsonify({
            "status": "Error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })


@app.route('/about')
def about():
    return render_template('about.html')

# Logout route
@app.route('/logout')
def logout():
    try:
        # End Firestore session if exists
        if session.get('user_id') and session.get('session_id') and firestore_db:
            session_ref = firestore_db.collection('sessions').document(session['session_id'])
            session_ref.update({
                'end_time': SERVER_TIMESTAMP,
                'status': 'completed'
            })
    except Exception as e:
        print(f"Error ending session: {e}")
    
    # Clear the session
    session.clear()
    
    # Return a response that will trigger frontend cleanup
    return redirect(url_for('landing'))

@app.route('/check-session')
def check_session():
    if not session.get('logged_in'):
        return "Not logged in"
    return jsonify({
        'username': session.get('username'),
        'user_id': session.get('user_id'),
        'session_id': session.get('session_id')
    })


@app.post('/debug/mock-flow')
def debug_mock_flow():
    """Emit a clearly marked simulation to validate dashboard notification delivery."""
    if not settings.debug_routes or not is_local_request():
        return jsonify({"error": "not_found"}), 404

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    incident = incident_manager.record(
        classification="Simulated Attack",
        source_ip="192.168.1.50",
        destination_ip="192.168.1.10",
        protocol="TCP",
        risk_level="high",
        attack_probability=0.93,
        flow_id="simulation",
    )
    runtime_metrics.increment("simulated_alerts_total")
    mock_result = [
        "simulation", "192.168.1.50", "51324", "192.168.1.10", "5000",
        "TCP", timestamp, timestamp, "safe_traffic_test.py", "simulation",
        "Simulated Attack", 0.93, "High",
    ]
    socketio.emit(
        "newresult",
        {
            "result": mock_result,
            "ips": [{"SourceIP": "192.168.1.50", "count": incident.event_count}],
            "risk_level": "high",
            "classification": "Simulated Attack",
            "simulated": True,
            "incident": incident.to_dict(),
        },
        namespace="/test",
    )
    return jsonify({
        "success": True,
        "message": "Simulated attack alert emitted",
        "incident": incident.to_dict(),
    })


@app.before_request
def ensure_capture_service():
    if settings.capture_enabled and not capture_service.running:
        capture_service.start()


@socketio.on('connect', namespace='/test')
def test_connect():
    if settings.capture_enabled and not capture_service.running:
        capture_service.start()
    logger.info("Dashboard client connected")


@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    logger.info("Dashboard client disconnected")


def cleanup_on_shutdown():
    try:
        if capture_service.running:
            capture_service.stop(flush=True)
    except Exception:
        logger.exception("Capture service shutdown failed")


atexit.register(cleanup_on_shutdown)


if __name__ == '__main__':
    if settings.capture_enabled:
        capture_service.start()
    socketio.run(
        app,
        host=os.environ.get("NETMASK_HOST", "127.0.0.1"),
        port=int(os.environ.get("NETMASK_PORT", "5000")),
        debug=settings.debug,
        allow_unsafe_werkzeug=not settings.production,
        use_reloader=False,
    )