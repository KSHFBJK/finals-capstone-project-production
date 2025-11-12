# ============================================================
# app.py — PhishGuard App (User + Admin)
# ============================================================

import os
import json
import uuid
import traceback
from datetime import datetime
from functools import wraps
from flask import (
    Flask, render_template, request, jsonify,
    send_from_directory, make_response, redirect,
    url_for, session
)
from werkzeug.utils import secure_filename
from predictor import detect_phishing, retrain_model, train_from_csv

# ============================================================
# App Configuration
# ============================================================
APP = Flask(__name__, template_folder="templates", static_folder="static")
APP.secret_key = "phisguard_secret_key"

APP.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max upload

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
    "dark_mode": False,
    "last_updated": datetime.utcnow().isoformat(),
    "admin_pass": "admin123"  # simple password
}

HISTORY_LIMIT = 1000

# ============================================================
# JSON Utilities
# ============================================================
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
        json.dump(data, f, indent=2, ensure_ascii=False)

def get_settings():
    """Ensure all default keys exist."""
    data = load_json(SETTINGS_FILE, DEFAULT_SETTINGS.copy())
    for key, value in DEFAULT_SETTINGS.items():
        if key not in data:
            data[key] = value
    return data

def save_settings(data):
    data["last_updated"] = datetime.utcnow().isoformat()
    save_json(SETTINGS_FILE, data)

if not os.path.exists(HISTORY_FILE):
    save_json(HISTORY_FILE, [])

# ============================================================
# Authentication Decorator
# ============================================================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated

# ============================================================
# Visitor Cookie Utility
# ============================================================
def ensure_visitor(resp):
    vid = request.cookies.get("visitor_id")
    if not vid:
        vid = uuid.uuid4().hex[:16]
        resp.set_cookie("visitor_id", vid, max_age=60*60*24*365)
    return resp

# ============================================================
# User Routes
# ============================================================
@APP.route("/")
def index():
    settings = get_settings()
    resp = make_response(render_template("scanner.html", settings=settings, current_year=datetime.utcnow().year))
    return ensure_visitor(resp)

@APP.route("/scan", methods=["POST"])
def scan():
    try:
        visitor_id = request.cookies.get("visitor_id") or uuid.uuid4().hex[:16]
        settings = get_settings()
        url_text = (request.form.get("url") or request.form.get("input_text") or "").strip()
        file = request.files.get("file")
        results = []

        if file and file.filename:
            filename = secure_filename(file.filename)
            path = os.path.join(UPLOAD_DIR, filename)
            file.save(path)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                content = None
            r = detect_phishing(content or path, settings)
            r.update({"type": "file", "uploaded_file": filename})
            results.append(r)

        if url_text:
            r = detect_phishing(url_text, settings)
            r.update({"type": "url", "uploaded_file": None})
            results.append(r)

        if not results:
            return jsonify({"error": "No URL or file provided"}), 400

        # Save history
        hist = load_json(HISTORY_FILE, [])
        for r in results:
            r.update({
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "user_id": visitor_id,
                "ml_probability": float(r.get("ml_probability", 0.0)),
                "heuristic_score": float(r.get("heuristic_score", 0.0)),
                "final_score": float(r.get("final_score", 0.0))
            })
            hist.insert(0, r)
        hist = hist[:HISTORY_LIMIT]
        save_json(HISTORY_FILE, hist)

        return jsonify(results[0] if len(results) == 1 else results)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Internal server error", "detail": str(e)}), 500

@APP.route("/history")
def history():
    visitor_id = request.cookies.get("visitor_id")
    hist = load_json(HISTORY_FILE, [])
    own = [h for h in hist if h.get("user_id") == visitor_id] if visitor_id else []
    if request.args.get("json") == "1":
        return jsonify(own)
    return render_template("history.html", history=own, current_year=datetime.utcnow().year)

@APP.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=False)

@APP.route("/_health")
def health():
    return jsonify({"status":"ok","time": datetime.utcnow().isoformat()})

# ============================================================
# Admin Routes
# ============================================================
ADMIN_ROUTE = "/__admin_portal__"

@APP.route(f"{ADMIN_ROUTE}/login", methods=["GET","POST"])
def admin_login():
    error = ""
    if request.method == "POST":
        entered = request.form.get("password","")
        settings = get_settings()
        if entered == settings.get("admin_pass","admin123"):
            session["admin_logged_in"] = True
            return redirect(f"{ADMIN_ROUTE}/dashboard")
        error = "Incorrect password"
    return render_template("admin_login.html", error=error)

@APP.route(f"{ADMIN_ROUTE}/logout")
@login_required
def admin_logout():
    session.clear()
    return redirect(f"{ADMIN_ROUTE}/login")

@APP.route(f"{ADMIN_ROUTE}/dashboard")
@login_required
def admin_dashboard():
    return render_template("admin_dashboard.html")

# ============================================================
# Admin APIs
# ============================================================
@APP.route(f"{ADMIN_ROUTE}/api/settings", methods=["GET"])
@login_required
def api_get_settings():
    return jsonify(get_settings())

@APP.route(f"{ADMIN_ROUTE}/api/settings/save", methods=["POST"])
@login_required
def api_save_settings():
    incoming = request.get_json(force=True)
    settings = get_settings()
    settings.update(incoming)
    save_settings(settings)
    return jsonify({"status":"saved","settings":settings})

@APP.route(f"{ADMIN_ROUTE}/api/domain/add", methods=["POST"])
@login_required
def api_domain_add():
    domain = (request.get_json(force=True) or {}).get("domain","").strip().lower()
    if not domain:
        return jsonify({"error":"no domain"}),400
    settings = get_settings()
    if domain not in settings["trusted_domains"]:
        settings["trusted_domains"].append(domain)
        save_settings(settings)
    return jsonify({"status":"added","trusted_domains":settings["trusted_domains"]})

@APP.route(f"{ADMIN_ROUTE}/api/domain/remove", methods=["POST"])
@login_required
def api_domain_remove():
    domain = (request.get_json(force=True) or {}).get("domain","").strip().lower()
    settings = get_settings()
    if domain in settings["trusted_domains"]:
        settings["trusted_domains"].remove(domain)
        save_settings(settings)
    return jsonify({"status":"removed","trusted_domains":settings["trusted_domains"]})

@APP.route(f"{ADMIN_ROUTE}/api/history/clear", methods=["POST"])
@login_required
def api_history_clear():
    save_json(HISTORY_FILE, [])
    return jsonify({"status":"cleared"})

@APP.route(f"{ADMIN_ROUTE}/api/retrain", methods=["POST"])
@login_required
def api_retrain():
    try:
        retrain_model()
    except Exception as e:
        return jsonify({"status":"error","error":str(e)}),500
    return jsonify({"status":"retrained"})

@APP.route(f"{ADMIN_ROUTE}/api/upload_csv", methods=["POST"])
@login_required
def api_upload_csv():
    if "file" not in request.files:
        return jsonify({"error":"no file"}),400
    f = request.files["file"]
    fn = secure_filename(f.filename)
    path = os.path.join(UPLOAD_DIR, fn)
    f.save(path)
    try:
        train_from_csv(path)
    except Exception as e:
        return jsonify({"error":str(e)}),500
    return jsonify({"status":"uploaded","filename":fn})

# ============================================================
# Run App
# ============================================================
if __name__ == "__main__":
    from waitress import serve
    print("🚀 PhisGuard app running on http://127.0.0.1:8080")
    serve(APP, host="0.0.0.0", port=8080)
