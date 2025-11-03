# admin_app.py
import os, json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from functools import wraps
from werkzeug.utils import secure_filename
from predictor import train_from_csv, retrain_model

APP = Flask(__name__, template_folder="templates", static_folder="static")
APP.secret_key = "supersecret_admin_key"

UPLOAD_FOLDER = "uploads"
DATA_DIR = "data"
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

ADMIN_USER = "admin"
ADMIN_PASS = "changeme"

# Login Decorator
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# JSON helpers
def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return default

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# Routes
@APP.route("/")
def root():
    return redirect(url_for("login"))

@APP.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        if request.form.get("username") == ADMIN_USER and request.form.get("password") == ADMIN_PASS:
            session["logged_in"] = True
            return redirect(url_for("admin_home"))
        msg = "❌ Invalid username or password"
    return render_template("login.html", msg=msg)

@APP.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

@APP.route("/admin")
@login_required
def admin_home():
    settings = load_json(SETTINGS_FILE, {"threshold": 0.6, "ml_weight": 0.8, "trusted_domains": []})
    history = load_json(HISTORY_FILE, [])
    return render_template("admin.html", title="PhisGuard Admin", settings=settings, history=history)

@APP.route("/admin/save", methods=["POST"])
@login_required
def save_settings():
    data = request.get_json(force=True)
    settings = {
        "threshold": float(data.get("threshold", 0.6)),
        "ml_weight": float(data.get("ml_weight", 0.8)),
        "trusted_domains": data.get("trusted_domains", []),
        "last_updated": datetime.utcnow().isoformat()
    }
    save_json(SETTINGS_FILE, settings)
    return jsonify({"status": "saved", "settings": settings})

@APP.route("/admin/clear_history", methods=["POST"])
@login_required
def clear_history():
    save_json(HISTORY_FILE, [])
    return jsonify({"status": "history_cleared"})

@APP.route("/admin/upload_csv", methods=["POST"])
@login_required
def upload_csv():
    file = request.files.get("csvfile")
    if not file or not file.filename.endswith(".csv"):
        return jsonify({"error": "CSV file required"}), 400
    path = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
    file.save(path)
    try:
        train_from_csv(path)
        return jsonify({"status": "trained", "file": file.filename})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@APP.route("/admin/retrain", methods=["POST"])
@login_required
def retrain():
    try:
        retrain_model()
        return jsonify({"status": "retrained"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("🧠 Admin Server running → http://127.0.0.1:5050/login")
    APP.run(host="0.0.0.0", port=5050, debug=True)
