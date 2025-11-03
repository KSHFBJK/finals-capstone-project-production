# predictor.py (FINALIZED)
import os, re, json, joblib, numpy as np, pandas as pd
from datetime import datetime
from urllib.parse import urlparse
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.utils import shuffle

from features import extract_features_from_url, FEATURE_NAMES, TRUSTED_DOMAINS, SUSPICIOUS_TOKENS

# ===============================
# CONFIGURATION
# ===============================
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)
MODEL_PATH = os.path.join(MODEL_DIR, "ensemble_model.joblib")

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)
MODEL_STATS_FILE = os.path.join(DATA_DIR, "model_stats.json")

DEFAULT_ML_WEIGHT = 0.8
DEFAULT_SUS_WORDS = SUSPICIOUS_TOKENS + ["password", "reset", "urgent", "prize", "free", "winner"]

# ===============================
# BASIC HELPERS
# ===============================
PUNYCODE_RE = re.compile(r"xn--", re.IGNORECASE)
ZERO_WIDTH_RE = re.compile(r"[\u200B\u200C\u200D\uFEFF]")
NON_ASCII_RE = re.compile(r"[^\x00-\x7F]")

def _safe_json_load(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def _safe_json_save(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# ===============================
# SYNTHETIC TRAINING DATA
# ===============================
def _generate_synthetic_dataset(n=2000, seed=42):
    rng = np.random.RandomState(seed)
    rows, labels = [], []
    benign = ["openai.com", "github.com", "python.org", "wikipedia.org", "example.com"]
    phish_tokens = ["secure-login", "verify-account", "free-gift", "bank-update", "login"]

    for _ in range(n):
        if rng.rand() < 0.5:
            token = rng.choice(phish_tokens)
            url = f"http://{token}{rng.randint(1,999)}.com/{''.join(rng.choice(list('abcdefghijklmnopqrstuvwxyz0123456789'), rng.randint(4,20)))}"
            label = 1
        else:
            dom = rng.choice(benign)
            url = f"https://{dom}/{rng.choice(['', 'blog', 'docs'])}"
            label = 0
        rows.append(extract_features_from_url(url))
        labels.append(label)

    return np.vstack(rows), np.array(labels)

# ===============================
# MODEL CREATION & LOADING
# ===============================
def _build_estimators():
    return {
        "lr": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000)),
        "rf": RandomForestClassifier(n_estimators=150, n_jobs=-1, random_state=1),
        "nb": make_pipeline(StandardScaler(), GaussianNB()),
    }

def _train_and_save_model(path=MODEL_PATH, samples=2000):
    X, y = _generate_synthetic_dataset(samples)
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, stratify=y, random_state=1)
    estimators = _build_estimators()
    fitted = []

    for name, est in estimators.items():
        est.fit(X_train, y_train)
        fitted.append((name, est))

    ensemble = VotingClassifier(estimators=fitted, voting="soft", n_jobs=-1)
    ensemble.fit(X_train, y_train)
    joblib.dump(ensemble, path)
    print(f"[predictor] ✅ Model trained and saved to {path}")
    return ensemble

def _load_or_train(path=MODEL_PATH):
    if os.path.exists(path):
        try:
            model = joblib.load(path)
            _ = model.predict_proba(np.zeros((1, len(FEATURE_NAMES))))
            print("[predictor] ✅ Model loaded from disk")
            return model
        except Exception:
            print("[predictor] ⚠️ Corrupted model, retraining...")
    return _train_and_save_model(path)

ENSEMBLE_MODEL = _load_or_train()

# ===============================
# ANALYSIS HELPERS
# ===============================
def _count_suspicious_words(text: str, words=None):
    words = words or DEFAULT_SUS_WORDS
    found = [w for w in words if w in text.lower()]
    return len(found), found

def _unicode_obfuscation_score(text: str):
    if not text:
        return 0.0
    total = len(text)
    non_ascii = len(NON_ASCII_RE.findall(text))
    score = min(0.6, (non_ascii / (total + 1)) * 1.5)
    if ZERO_WIDTH_RE.search(text):
        score = max(score, 0.6)
    if PUNYCODE_RE.search(text):
        score = max(score, 0.95)
    return float(score)

# ===============================
# ENSEMBLE PREDICTION
# ===============================
def _ensemble_proba(features):
    per_model = {}
    try:
        avg = float(ENSEMBLE_MODEL.predict_proba(features.reshape(1, -1))[0, 1])
        if hasattr(ENSEMBLE_MODEL, "named_estimators_"):
            for name, est in ENSEMBLE_MODEL.named_estimators_.items():
                try:
                    per_model[name] = float(est.predict_proba(features.reshape(1, -1))[0, 1])
                except Exception:
                    per_model[name] = 0.0
        return avg, per_model
    except Exception as e:
        print(f"[predictor] Ensemble error: {e}")
        return 0.0, {}

# ===============================
# MAIN FUNCTION
# ===============================
def detect_phishing(input_text: str, settings: dict = None, threshold: float = None):
    """Detect phishing from URL or file text (auto-detect type)."""
    if not isinstance(input_text, str):
        raise ValueError("input_text must be string")

    settings = settings or {}
    trusted_domains = settings.get("trusted_domains", TRUSTED_DOMAINS)
    ml_weight = float(settings.get("ml_weight", DEFAULT_ML_WEIGHT))
    threshold_use = float(threshold or settings.get("threshold", 0.6))

    text = input_text.strip()
    is_url = re.match(r"^(https?:\/\/|www\.)", text) or "." in text

    feats = extract_features_from_url(text if is_url else "textinput.local")
    feats_arr = np.array(feats, dtype=float)
    ml_prob, per_model = _ensemble_proba(feats_arr)

    # --- Heuristics ---
    reasons, heur_score = [], 0.0
    domain = ""
    try:
        parsed = urlparse(text if is_url else "")
        domain = (parsed.hostname or "").lower() if parsed.hostname else ""
    except Exception:
        pass

    trusted_found = any(domain.endswith(td) for td in trusted_domains if td)
    if trusted_found:
        reasons.append("✅ Domain is in trusted whitelist")

    wcount, matched = _count_suspicious_words(text)
    if wcount:
        reasons.append(f"Suspicious terms: {', '.join(sorted(set(matched)))}")
        heur_score = max(heur_score, min(0.9, 0.2 + 0.05 * wcount))

    uni_score = _unicode_obfuscation_score(text)
    if uni_score > 0:
        heur_score = max(heur_score, uni_score)
        reasons.append("Unicode or obfuscated text detected")

    if "@" in text:
        reasons.append("Contains '@' symbol")
        heur_score = max(heur_score, 0.7)

    # Final combine
    heur_score = float(min(1.0, heur_score))
    final_score = float(ml_prob * ml_weight + heur_score * (1 - ml_weight))
    if trusted_found:
        final_score *= 0.3

    verdict = (
        "phishing" if final_score >= threshold_use
        else "suspicious" if final_score >= threshold_use * 0.6
        else "legitimate"
    )

    return {
        "input": text,
        "domain": domain or "(file content)" if not is_url else domain,
        "type": "url" if is_url else "file",
        "ml_probability": round(ml_prob, 4),
        "heuristic_score": round(heur_score, 4),
        "final_score": round(final_score, 4),
        "verdict": verdict,
        "threshold": float(threshold_use),
        "trusted": trusted_found,
        "reasons": reasons,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "per_model": per_model,
    }

# ===============================
# TRAINING FUNCTIONS
# ===============================
def retrain_model(samples: int = 2500):
    """Retrain using synthetic dataset."""
    global ENSEMBLE_MODEL
    ENSEMBLE_MODEL = _train_and_save_model(MODEL_PATH, samples)
    return True

def train_from_csv(csv_path: str, url_col="url", label_col="label", save_path=MODEL_PATH):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    df = pd.read_csv(csv_path)
    if url_col not in df.columns or label_col not in df.columns:
        raise ValueError(f"CSV must contain columns '{url_col}' and '{label_col}'")

    X = np.vstack([extract_features_from_url(str(u)) for u in df[url_col]])
    y = df[label_col].astype(int).to_numpy()

    X, y = shuffle(X, y, random_state=42)
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.15, stratify=y)

    estimators = _build_estimators()
    fitted = [(n, e.fit(X_train, y_train)) for n, e in estimators.items()]
    ensemble = VotingClassifier(estimators=fitted, voting="soft")
    ensemble.fit(X_train, y_train)
    joblib.dump(ensemble, save_path)
    global ENSEMBLE_MODEL
    ENSEMBLE_MODEL = ensemble
    print(f"[predictor] ✅ Retrained and saved model to {save_path}")
    return True
