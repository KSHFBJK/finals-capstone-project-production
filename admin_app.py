# ============================================================
# admin_app.py — Administrator Dashboard (Fully connected)
# ============================================================

import os, json
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from predictor import retrain_model, train_from_csv

# ------------------------------
# App Config
# ------------------------------
APP = Flask(__name__, template_folder="templates", static_folder="static")
APP.secret_key = os.environ.get("ADMIN_FLASK_SECRET", "admin_secret_change_me")

DATA_DIR = "data"
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

DEFAULT_SETTINGS = {
    "threshold": 0.6,
    "ml_weight": 0.85,
    "trusted_domains": ["google.com", "openai.com", "github.com"],
    "last_updated": datetime.utcnow().isoformat()
}

ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123")

# ------------------------------
# JSON Utilities
# ------------------------------
def load_json(path, default):
    if not os.path.exists(path):
        save_json(path, default)
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# ------------------------------
# Auth Decorator
# ------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ------------------------------
# Routes
# ------------------------------
@APP.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        p = request.form.get("password", "")
        if p == ADMIN_PASS:
            session["admin_logged_in"] = True
            return redirect(url_for("admin_dashboard"))
        error = "Incorrect password"
    return render_template("admin_login.html", error=error)

@APP.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

@APP.route("/admin")
@login_required
def admin_dashboard():
    return render_template("admin_dashboard.html")

# ------------------------------
# API Endpoints
# ------------------------------
@APP.route("/api/settings", methods=["GET"])
@login_required
def api_get_settings():
    return jsonify(load_json(SETTINGS_FILE, DEFAULT_SETTINGS))

@APP.route("/api/settings/save", methods=["POST"])
@login_required
def api_save_settings():
    data = request.get_json(force=True)
    data["last_updated"] = datetime.utcnow().isoformat()
    save_json(SETTINGS_FILE, data)
    return jsonify({"status": "saved", "settings": data})

@APP.route("/api/domain/add", methods=["POST"])
@login_required
def api_domain_add():
    data = request.get_json(force=True)
    domain = (data or {}).get("domain", "").strip().lower()
    if not domain:
        return jsonify({"error": "no domain"}), 400
    settings = load_json(SETTINGS_FILE, DEFAULT_SETTINGS)
    if domain not in settings["trusted_domains"]:
        settings["trusted_domains"].append(domain)
        settings["last_updated"] = datetime.utcnow().isoformat()
        save_json(SETTINGS_FILE, settings)
    return jsonify({"status": "added", "trusted_domains": settings["trusted_domains"]})

@APP.route("/api/domain/remove", methods=["POST"])
@login_required
def api_domain_remove():
    data = request.get_json(force=True)
    domain = (data or {}).get("domain", "").strip().lower()
    settings = load_json(SETTINGS_FILE, DEFAULT_SETTINGS)
    if domain in settings["trusted_domains"]:
        settings["trusted_domains"].remove(domain)
        settings["last_updated"] = datetime.utcnow().isoformat()
        save_json(SETTINGS_FILE, settings)
    return jsonify({"status": "removed", "trusted_domains": settings["trusted_domains"]})

@APP.route("/api/history", methods=["GET"])
@login_required
def api_history():
    hist = load_json(HISTORY_FILE, [])
    verdict = request.args.get("verdict")
    user_id = request.args.get("user_id")
    domain = request.args.get("domain")

    if verdict:
        hist = [h for h in hist if h.get("verdict") == verdict]
    if user_id:
        hist = [h for h in hist if h.get("user_id") == user_id]
    if domain:
        hist = [h for h in hist if domain.lower() in (h.get("domain") or h.get("input", "")).lower()]
    return jsonify(hist)

@APP.route("/api/history/remove", methods=["POST"])
@login_required
def api_history_remove():
    data = request.get_json(force=True)
    index = data.get("index")
    hist = load_json(HISTORY_FILE, [])
    if 0 <= index < len(hist):
        hist.pop(index)
        save_json(HISTORY_FILE, hist)
    return jsonify({"status": "removed"})

@APP.route("/api/history/clear", methods=["POST"])
@login_required
def api_history_clear():
    save_json(HISTORY_FILE, [])
    return jsonify({"status": "cleared"})

@APP.route("/api/history/download", methods=["GET"])
@login_required
def api_history_download():
    hist = load_json(HISTORY_FILE, [])
    return jsonify({"history": hist})

@APP.route("/api/upload_csv", methods=["POST"])
@login_required
def api_upload_csv():
    if "file" not in request.files:
        return jsonify({"error": "no file"}), 400
    f = request.files["file"]
    fn = secure_filename(f.filename)
    path = os.path.join(UPLOAD_DIR, fn)
    f.save(path)
    try:
        train_from_csv(path)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"status": "uploaded", "filename": fn})

@APP.route("/api/retrain", methods=["POST"])
@login_required
def api_retrain():
    try:
        retrain_model()
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500
    return jsonify({"status": "retrained"})

@APP.route("/uploads/<path:filename>")
@login_required
def serve_upload(filename):
    return send_from_directory(UPLOAD_DIR, filename)

# ------------------------------
# Run App
# ------------------------------
if __name__ == "__main__":
    APP.run(host="0.0.0.0", port=5050, debug=True)
