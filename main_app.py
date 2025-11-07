# main_app.py — User-facing PhisGuard (fixed history + robust endpoints)
import os, json, uuid, traceback
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory, make_response
from werkzeug.utils import secure_filename
from predictor import detect_phishing

# ----- Config -----
APP = Flask(__name__, template_folder="templates", static_folder="static")
APP.secret_key = os.environ.get("USER_FLASK_SECRET", "user_secret_change_me")

DATA_DIR = "data"
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

DEFAULT_SETTINGS = {
    "threshold": 0.55,
    "ml_weight": 0.9,
    "trusted_domains": ["google.com", "openai.com", "github.com"]
}

# Ensure history file exists and is valid JSON
def _ensure_history_file():
    if not os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)
    else:
        # try to read; if corrupted, replace with empty list
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                json.load(f)
        except Exception:
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump([], f)

_ensure_history_file()

# JSON helpers
def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

# visitor cookie
def ensure_visitor(resp):
    vid = request.cookies.get("visitor_id")
    if not vid:
        vid = uuid.uuid4().hex[:16]
        resp.set_cookie("visitor_id", vid, max_age=60*60*24*365)
    return resp

# ----- Routes -----
@APP.route("/")
def index():
    # render scanner template (your scanner.html)
    settings = load_json(SETTINGS_FILE, DEFAULT_SETTINGS)
    resp = make_response(render_template("scanner.html", settings=settings, current_year=datetime.utcnow().year))
    return ensure_visitor(resp)

@APP.route("/scan", methods=["POST"])
def scan():
    """
    Accepts form-data: url (text) and/or file.
    Returns JSON — single result or list (frontend expects JSON).
    Also saves to history.json (latest first).
    """
    try:
        visitor_id = request.cookies.get("visitor_id") or uuid.uuid4().hex[:16]
        settings = load_json(SETTINGS_FILE, DEFAULT_SETTINGS)

        url_text = (request.form.get("url") or request.form.get("input_text") or "").strip()
        file = request.files.get("file")

        results = []

        # If file uploaded, save then try read as text then scan content
        if file and file.filename:
            filename = secure_filename(file.filename)
            save_path = os.path.join(UPLOAD_DIR, filename)
            file.save(save_path)

            # attempt to read file as text; if fails, pass file path or name
            content = None
            try:
                with open(save_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                content = None

            input_for_predictor = content if content else save_path
            r = detect_phishing(input_for_predictor, settings)
            r["type"] = "file"
            r["uploaded_file"] = filename
            results.append(r)

        # If url/text provided — scan it as well
        if url_text:
            r = detect_phishing(url_text, settings)
            r["type"] = "url"
            r["uploaded_file"] = None
            results.append(r)

        if not results:
            return jsonify({"error": "No URL or file provided"}), 400

        # Attach timestamp/userid and persist to history
        history = load_json(HISTORY_FILE, [])
        for r in results:
            r.setdefault("timestamp", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
            r.setdefault("user_id", visitor_id)
            # sanitize fields that may not be serializable
            r["ml_probability"] = float(r.get("ml_probability", 0.0))
            r["heuristic_score"] = float(r.get("heuristic_score", 0.0))
            r["final_score"] = float(r.get("final_score", 0.0))
            history.insert(0, r)
        # keep history size reasonable
        history = history[:1000]
        save_json(HISTORY_FILE, history)

        # Return only the first result (frontend expects single object or array)
        return jsonify(results[0] if len(results) == 1 else results)
    except Exception as e:
        # log traceback
        traceback.print_exc()
        return jsonify({"error": "Internal server error", "detail": str(e)}), 500

@APP.route("/history")
def history():
    """
    If ?json=1 returns user's history as JSON (filtered by visitor_id cookie).
    Otherwise renders history template (history.html) passing user's history.
    """
    visitor_id = request.cookies.get("visitor_id")
    # ensure history file exists
    _ensure_history_file()
    history = load_json(HISTORY_FILE, [])

    if request.args.get("json") == "1":
        if not visitor_id:
            return jsonify([])  # no cookie yet
        own = [h for h in history if h.get("user_id") == visitor_id]
        return jsonify(own)
    else:
        # render template with user's own history (for server-rendered page)
        own = [h for h in history if h.get("user_id") == visitor_id] if visitor_id else []
        return render_template("history.html", history=own, current_year=datetime.utcnow().year)

@APP.route("/uploads/<path:filename>")
def uploaded_file(filename):
    # safe serve uploads
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=False)

# simple health endpoint
@APP.route("/_health")
def health():
    return jsonify({"status":"ok","time": datetime.utcnow().isoformat()})

# ----- Run -----
if __name__ == "__main__":
    APP.run(host="0.0.0.0", port=5000, debug=True)
