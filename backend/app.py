import json
import hashlib
import time
import os
import numpy as np
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from sklearn.ensemble import IsolationForest
from database import initialize_database, get_connection
from risk_engine import calculate_risk
from crypto import encrypt, decrypt, encrypt_log, decrypt_log

def normalize_json_field(field):
    if isinstance(field, str):
        try:
            return json.loads(field)
        except:
            return {}
    return field if isinstance(field, dict) else {}

SECRET_KEY     = "pentastic_secret"
ADMIN_PASSWORD = "admin@pentastic"   # change this to your own password
BEHAVIOR_LOG_FILE = "behavior_logs.json"

app = Flask(__name__)
CORS(app)

# ══════════════════════════════════════════════════════════════════════════════
#  ISOLATION FOREST — Behavior ML
# ══════════════════════════════════════════════════════════════════════════════

def load_behavior_logs():
    if os.path.exists(BEHAVIOR_LOG_FILE):
        with open(BEHAVIOR_LOG_FILE, "r") as f:
            return json.load(f)
    return []

def save_behavior_log(entry):
    logs = load_behavior_logs()
    logs.append(entry)
    with open(BEHAVIOR_LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)

def extract_features(data):
    """
    7 behavioral features for Isolation Forest:
    1. session_duration_sec     — how long they stayed
    2. avg_mouse_speed          — pixels/sec (bots too fast/slow)
    3. click_rate_per_min       — clicks per minute
    4. avg_file_hover_time_sec  — time hovering over files
    5. file_access_count        — how many files accessed
    6. login_hour               — hour of login (0-23)
    7. triggered_honeyfile      — 1 if clicked honey file
    """
    return [
        float(data.get("session_duration_sec", 0)),
        float(data.get("avg_mouse_speed", 0)),
        float(data.get("click_rate_per_min", 0)),
        float(data.get("avg_file_hover_time_sec", 0)),
        float(data.get("file_access_count", 0)),
        float(data.get("login_hour", 12)),
        1.0 if data.get("triggered_honeyfile") else 0.0,
    ]

def train_if_model():
    logs = load_behavior_logs()
    if len(logs) < 5:
        return None
    X = np.array([extract_features(log) for log in logs])
    model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
    model.fit(X)
    return model

def get_if_bonus(model, features):
    """
    Convert IF score → extra risk points
    Score < -0.1  → very anomalous  → +20
    Score 0–-0.1  → mildly suspicious → +10
    Score > 0     → normal           →  +0
    """
    if model is None:
        return 0, None, "collecting_data"

    score = float(model.decision_function([features])[0])

    if score < -0.1:
        return 20, round(score, 4), "Anomalous behavior detected by ML (+20)"
    elif score < 0:
        return 10, round(score, 4), "Mildly suspicious behavior (+10)"
    else:
        return 0, round(score, 4), None

# ══════════════════════════════════════════════════════════════════════════════
#  ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

# -----------------------------
# HOME
# -----------------------------
@app.route("/")
def home():
    return "Pentastic Backend Running"

# -----------------------------
# SECURE LOG INGESTION
# -----------------------------
@app.route("/ingest-log", methods=["POST"])
def ingest_log():
    data = request.json

    username  = data.get("username")
    timestamp = data.get("timestamp")

    # 🔐 Signature verification (skip if not provided)
    received_signature = request.headers.get("X-Signature")
    if received_signature:
        message = f"{username}{timestamp}{SECRET_KEY}"
        generated_signature = hashlib.sha256(message.encode()).hexdigest()

        if received_signature != generated_signature:
            return jsonify({"error": "Tampered Log Detected"}), 401

        if timestamp and abs(time.time() - int(timestamp)) > 300:
            return jsonify({"error": "Replay Attack"}), 401

    login_time      = data.get("login_time")
    ip_address      = data.get("ip_address")
    device          = data.get("device")
    folder          = data.get("folder_accessed", "")
    failed_attempts = int(data.get("failed_attempts", 0))

    conn   = get_connection()
    cursor = conn.cursor()

    # Get existing failed attempts from DB for this user
    existing = conn.execute(
        "SELECT failed_attempts FROM users WHERE username=?", (username,)
    ).fetchone()

    db_failed    = existing["failed_attempts"] if existing and "failed_attempts" in existing.keys() else 0
    # Always keep the highest failed attempts — never reset on successful login
    total_failed = db_failed + failed_attempts

    # 🔹 Classic risk engine
    risk_score, status, reason = calculate_risk(
        login_time, ip_address, device, folder, total_failed
    )

    local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT OR IGNORE INTO users (username, role, failed_attempts)
        VALUES (?, ?, ?)
    """, (username, "employee", total_failed))

    cursor.execute("""
        UPDATE users
        SET risk_score=?, status=?, last_updated=?, failed_attempts=?
        WHERE username=?
    """, (risk_score, status, local_time, total_failed, username))

    # 🔐 Encrypt sensitive fields before saving
    enc_username   = encrypt(username)
    enc_ip         = encrypt(ip_address)
    enc_device     = encrypt(device)

    cursor.execute("""
        INSERT INTO activity_logs
        (username, login_time, ip_address, device, folder_accessed, event_type, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (enc_username, login_time, enc_ip, enc_device, folder, "access", local_time))

    if status in ("SUSPICIOUS", "DECEPTION", "BLOCKED"):
        cursor.execute("""
            INSERT INTO alerts (username, risk_score, reason, confirmed, timestamp)
            VALUES (?, ?, ?, 0, ?)
        """, (username, risk_score, reason, local_time))

    conn.commit()
    conn.close()

    return jsonify({
        "risk_score": risk_score,
        "status":     status,
        "reason":     reason
    })

# -----------------------------
# BEHAVIOR ANALYSIS (ML)
# -----------------------------
@app.route("/analyze-behavior", methods=["POST"])
def analyze_behavior():
    data      = request.get_json()
    username  = data.get("username", "unknown")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Save behavior log for training
    save_behavior_log({**data, "timestamp": timestamp})

    # Extract features
    features = extract_features(data)

    # Run Isolation Forest
    model = train_if_model()
    if_bonus, if_score, if_reason = get_if_bonus(model, features)

    # Now fetch classic risk score from DB for this user
    conn = get_connection()
    user = conn.execute(
        "SELECT risk_score, status FROM users WHERE username=?", (username,)
    ).fetchone()
    conn.close()

    classic_score  = user["risk_score"] if user else 0
    classic_status = user["status"]     if user else "SAFE"

    # Combine classic + ML bonus
    final_score = min(int(classic_score) + if_bonus, 100)

    if final_score >= 70:
        final_status = "DECEPTION"
    elif final_score >= 40:
        final_status = "SUSPICIOUS"
    else:
        final_status = "SAFE"

    # Update DB with combined score if ML changed it
    if if_bonus > 0:
        local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET risk_score=?, status=?, last_updated=?
            WHERE username=?
        """, (final_score, final_status, local_time, username))

        if final_status in ("SUSPICIOUS", "DECEPTION") and if_reason:
            cursor.execute("""
                INSERT INTO alerts (username, risk_score, reason, confirmed, timestamp)
                VALUES (?, ?, ?, 0, ?)
            """, (username, final_score, if_reason, local_time))

        conn.commit()
        conn.close()

    model_status = "ok" if model else f"collecting_data ({len(load_behavior_logs())}/5 sessions)"

    emoji = "🚨" if final_status == "DECEPTION" else "⚠️ " if final_status == "SUSPICIOUS" else "✅"
    print(f"\n{emoji} {final_status} — User: {username}")
    print(f"   Final Score: {final_score} (Classic: {classic_score} + ML Bonus: {if_bonus})")
    if if_reason:
        print(f"   ML Reason: {if_reason}")

    return jsonify({
        "username":      username,
        "timestamp":     timestamp,
        "final_score":   final_score,
        "final_status":  final_status,
        "classic_score": classic_score,
        "if_bonus":      if_bonus,
        "if_score":      if_score,
        "if_reason":     if_reason,
        "model_status":  model_status,
        "breakdown": {
            "classic_risk":  classic_score,
            "ml_bonus":      if_bonus,
            "ml_anomaly":    if_bonus > 0,
            "honeyfile":     bool(data.get("triggered_honeyfile")),
        }
    })

# -----------------------------
# GET SINGLE USER STATUS
# -----------------------------
@app.route("/user-status/<username>", methods=["GET"])
def get_user_status(username):
    conn = get_connection()
    user = conn.execute(
        "SELECT status, risk_score FROM users WHERE username=?", (username,)
    ).fetchone()
    conn.close()

    if not user:
        return jsonify({"status": "SAFE", "risk_score": 0})

    return jsonify({
        "status":     user["status"],
        "risk_score": user["risk_score"]
    })

# -----------------------------
# GET USERS
# -----------------------------
@app.route("/users", methods=["GET"])
def get_users():
    conn  = get_connection()
    users = conn.execute("SELECT * FROM users ORDER BY risk_score DESC").fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

# -----------------------------
# GET ALERTS
# -----------------------------
@app.route("/alerts", methods=["GET"])
def get_alerts():
    conn   = get_connection()
    alerts = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC"
    ).fetchall()
    conn.close()
    return jsonify([dict(a) for a in alerts])

# -----------------------------
# HONEYFILE ACCESS
# -----------------------------
@app.route("/honeyfile-access", methods=["POST"])
def honeyfile_access():
    data     = request.json
    username = data.get("username")

    if not username:
        return jsonify({"error": "Username required"}), 400

    conn   = get_connection()
    cursor = conn.cursor()

    local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        UPDATE alerts SET confirmed=1
        WHERE username=? AND confirmed=0
    """, (username,))

    cursor.execute("""
        UPDATE users SET status='BLOCKED', risk_score=100, last_updated=?
        WHERE username=?
    """, (local_time, username))

    cursor.execute("""
        INSERT INTO activity_logs (username, event_type, folder_accessed, timestamp)
        VALUES (?, 'honeyfile_access', 'Decoy_Files', ?)
    """, (username, local_time))

    conn.commit()
    conn.close()

    return jsonify({"message": "User Blocked - Confirmed Attacker"})

# -----------------------------
# MANUAL STATUS UPDATE
# -----------------------------
@app.route("/update-status", methods=["POST"])
def update_status():
    data     = request.json
    username = data.get("username")
    status   = data.get("status")

    conn   = get_connection()
    cursor = conn.cursor()

    local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        UPDATE users SET status=?, last_updated=?
        WHERE username=?
    """, (status, local_time, username))

    conn.commit()
    conn.close()

    return jsonify({"message": "Status updated successfully"})

# -----------------------------
# GET ACTIVITY LOGS (admin only)
# -----------------------------
@app.route("/logs", methods=["GET"])
def get_logs():
    # 🔐 Admin password check via header
    admin_pass = request.headers.get("X-Admin-Password")
    if admin_pass != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized — admin access only"}), 401

    conn = get_connection()
    logs = conn.execute(
        "SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT 100"
    ).fetchall()
    conn.close()

    # 🔓 Decrypt sensitive fields before returning
    decrypted_logs = [decrypt_log(dict(l)) for l in logs]
    return jsonify(decrypted_logs)

# -----------------------------
# GET ML ANOMALIES
# -----------------------------
@app.route("/anomalies", methods=["GET"])
def get_anomalies():
    logs  = load_behavior_logs()
    model = train_if_model()

    if not model:
        return jsonify({"error": f"Need 5+ sessions, have {len(logs)} so far"}), 400

    anomalies = []
    for log in logs:
        features   = extract_features(log)
        prediction = model.predict([features])[0]
        score      = model.decision_function([features])[0]
        if prediction == -1:
            anomalies.append({**log, "if_score": round(float(score), 4)})

    return jsonify({"total_anomalies": len(anomalies), "anomalies": anomalies})

# -----------------------------
# DELETE USER (admin action)
# -----------------------------
@app.route("/delete-user", methods=["POST"])
def delete_user():
    data     = request.json
    username = data.get("username")

    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE username=?", (username,))
    cursor.execute("DELETE FROM alerts WHERE username=?", (username,))
    cursor.execute("DELETE FROM activity_logs WHERE username=?", (username,))
    conn.commit()
    conn.close()

    return jsonify({"message": f"User {username} deleted"})

# -----------------------------
# START SERVER
# -----------------------------

# -----------------------------
# LOGIN — checks if user blocked
# -----------------------------

# Default credentials for testing
# In production, store hashed passwords in DB
USERS_CREDENTIALS = {
    "admin":    "admin123",
    "john":     "john123",
    "attacker": "attacker123",
}

@app.route("/login", methods=["POST"])
def login():
    data     = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    conn = get_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username=?", (username,)
    ).fetchone()
    conn.close()

    # 🚫 BLOCKED check — always first, before anything else
    if user and user["status"] == "BLOCKED":
        print(f"🚫 Blocked user tried to login: {username}")
        return jsonify({"error": "Your account has been blocked. Contact administrator."}), 403

    # 🔐 Password check
    expected_password = USERS_CREDENTIALS.get(username)
    if not expected_password or password != expected_password:
        # Track failed attempt in DB
        local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR IGNORE INTO users (username, role, risk_score, status, failed_attempts, last_updated)
            VALUES (?, 'employee', 0, 'SAFE', 0, ?)
        """, (username, local_time))
        cursor.execute("""
            UPDATE users SET failed_attempts = failed_attempts + 1, last_updated=?
            WHERE username=?
        """, (local_time, username))
        conn.commit()
        conn.close()
        print(f"❌ Wrong password for: {username}")
        return jsonify({"error": "Invalid username or password"}), 401

    # ✅ Login success — create user in DB if not exists
    local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, role, risk_score, status, last_updated)
        VALUES (?, 'employee', 0, 'SAFE', ?)
    """, (username, local_time))
    conn.commit()
    conn.close()

    # Fetch current status and risk score to send back
    conn  = get_connection()
    udata = conn.execute("SELECT status, risk_score FROM users WHERE username=?", (username,)).fetchone()
    conn.close()

    status     = udata["status"]     if udata else "SAFE"
    risk_score = udata["risk_score"] if udata else 0

    print(f"✅ Login successful: {username} | Status: {status} | Risk: {risk_score}")
    return jsonify({
        "message":    "Login successful",
        "username":   username,
        "status":     status,
        "risk_score": risk_score
    }), 200

if __name__ == "__main__":
    print("🚀 Starting Pentastic Backend")
    initialize_database()
    app.run(host="0.0.0.0", port=5000, debug=True)