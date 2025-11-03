# main_app.py
import os, json, uuid
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from predictor import detect_phishing

APP = Flask(__name__, template_folder="templates", static_folder="static")
APP.secret_key = "phisguard_user_secret"

UPLOAD_FOLDER = "uploads"
DATA_DIR = "data"
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return default

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

@APP.route("/")
def home():
    settings = load_json(SETTINGS_FILE, {"threshold": 0.6, "ml_weight": 0.8, "trusted_domains": []})
    return render_template("index.html", title="PhisGuard Scanner", current_year=datetime.now().year, settings=settings)

@APP.route("/history.json")
def view_history():
    history = load_json(HISTORY_FILE, [])
    return jsonify(history)

@APP.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url", "").strip()
    file = request.files.get("file")
    settings = load_json(SETTINGS_FILE, {"threshold": 0.6, "ml_weight": 0.8, "trusted_domains": []})
    results = []

    user_id = str(uuid.uuid4())[:8]

    if url:
        r = detect_phishing(url, settings)
        r["user_id"] = user_id
        results.append(r)

    if file and file.filename:
        path = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
        file.save(path)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            r = detect_phishing(content, settings)
            r["user_id"] = user_id
            results.append(r)
        except Exception as e:
            return jsonify({"error": f"File scan failed: {str(e)}"}), 500

    history = load_json(HISTORY_FILE, [])
    for r in results:
        r["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        history.append(r)
    save_json(HISTORY_FILE, history)
    return jsonify(results)

if __name__ == "__main__":
    print("🧩 User Server running → http://127.0.0.1:5000/")
    APP.run(host="0.0.0.0", port=5000, debug=True)
