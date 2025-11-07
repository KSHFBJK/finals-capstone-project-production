# predictor.py — Hybrid Phishing Detector (Revised, Safe Threshold Handling, CSV Training)
import os, re, logging, numpy as np, pandas as pd
from datetime import datetime
from urllib.parse import urlparse
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.utils import shuffle
import xgboost as xgb
from catboost import CatBoostClassifier
import lightgbm as lgb
from features import extract_features_from_url, FEATURE_NAMES, TRUSTED_DOMAINS, SUSPICIOUS_TOKENS

logging.basicConfig(level=logging.INFO, format='[predictor] %(message)s')

DEFAULT_ML_WEIGHT = 0.6
DEFAULT_THRESHOLD = 0.55

ZERO_WIDTH_RE = re.compile(r"[\u200B\u200C\u200D\uFEFF]")
NON_ASCII_RE = re.compile(r"[^\x00-\x7F]")
PUNYCODE_RE = re.compile(r"xn--", re.IGNORECASE)
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)
MODEL_PATH = os.path.join(MODEL_DIR, "ensemble_model.joblib")

# ------------------------------
# ML Predictor
# ------------------------------
class MLPredictor:
    def __init__(self, model_path=MODEL_PATH):
        self.model_path = model_path
        self.model = self._load_or_train()

    def _build_estimators(self):
        return {
            "lr": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)),
            "rf": RandomForestClassifier(n_estimators=300, n_jobs=-1, class_weight="balanced_subsample", random_state=1),
            "nb": make_pipeline(StandardScaler(), GaussianNB()),
            "xgb": xgb.XGBClassifier(use_label_encoder=False, eval_metric="logloss", n_estimators=400, learning_rate=0.05, max_depth=6, n_jobs=-1, random_state=1),
            "cb": CatBoostClassifier(iterations=400, learning_rate=0.05, depth=8, loss_function="Logloss", verbose=0, random_seed=1),
            "lgb": lgb.LGBMClassifier(n_estimators=400, learning_rate=0.05, max_depth=7, num_leaves=31, min_child_samples=5, class_weight="balanced", n_jobs=-1, verbose=-1)
        }

    def _train_model(self, samples=3000):
        from predictor import generate_synthetic_dataset
        X, y = generate_synthetic_dataset(samples)
        X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, stratify=y, random_state=1)
        estimators = self._build_estimators()
        fitted = [(name, model.fit(X_train, y_train)) for name, model in estimators.items()]
        weights = [1, 1, 0.5, 2, 2.5, 2]
        ensemble = VotingClassifier(estimators=fitted, voting="soft", weights=weights, n_jobs=-1)
        ensemble.fit(X_train, y_train)
        import joblib
        joblib.dump(ensemble, self.model_path)
        logging.info(f"✅ ML Model trained and saved to {self.model_path}")
        return ensemble

    def _load_or_train(self):
        import joblib
        if os.path.exists(self.model_path):
            try:
                model = joblib.load(self.model_path)
                _ = model.predict_proba(np.zeros((1, len(FEATURE_NAMES))))
                logging.info("✅ ML Model loaded from disk")
                return model
            except:
                logging.warning("⚠️ ML Model corrupted, retraining...")
        return self._train_model()

    def predict_proba(self, features):
        avg = float(self.model.predict_proba(features.reshape(1, -1))[0, 1])
        per_model = {}
        if hasattr(self.model, "named_estimators_"):
            for name, est in self.model.named_estimators_.items():
                try:
                    per_model[name] = float(est.predict_proba(features.reshape(1, -1))[0, 1])
                except:
                    per_model[name] = 0.0
        return avg, per_model

    def retrain(self, samples=3000):
        self.model = self._train_model(samples)
        return True

ml_predictor = MLPredictor()

# ------------------------------
# Phishing Detector
# ------------------------------
class PhishingDetector:
    def __init__(self, ml_predictor, trusted_domains=None, ml_weight=DEFAULT_ML_WEIGHT):
        self.ml = ml_predictor
        self.trusted_domains = trusted_domains or TRUSTED_DOMAINS
        self.ml_weight = ml_weight

    def _heuristic_score(self, text, domain):
        heur_score = 0.0
        reasons = []

        trusted_found = any(domain.endswith(td) for td in self.trusted_domains if td)
        if trusted_found: reasons.append("✅ Domain is trusted")

        token_counts = [text.lower().count(t) for t in SUSPICIOUS_TOKENS if t in text.lower()]
        if token_counts:
            score = min(0.95, 0.2 + 0.1*np.log1p(sum(token_counts)))
            heur_score = max(heur_score, score)
            reasons.append(f"⚠️ Suspicious terms detected ({sum(token_counts)})")

        non_ascii = len(NON_ASCII_RE.findall(text))
        zero_width = len(ZERO_WIDTH_RE.findall(text))
        punycode = 1 if PUNYCODE_RE.search(domain) else 0
        if non_ascii > 0 or zero_width > 0 or punycode:
            heur_score = max(heur_score, 0.6)
            reasons.append("⚠️ Unicode/obfuscation detected")

        if IP_RE.match(domain):
            heur_score = max(heur_score, 0.8)
            reasons.append("⚠️ IP address used in domain")

        depth = domain.count('.')
        if depth > 2:
            heur_score = max(heur_score, 0.5)
            reasons.append(f"⚠️ Subdomain depth suspicious ({depth})")

        path_entropy = len(set(text)) / (len(text)+1)
        if path_entropy > 0.65: 
            heur_score = max(heur_score, 0.55)
            reasons.append("⚠️ High URL entropy (path/query)")

        if "@" in text: heur_score = max(heur_score,0.75); reasons.append("⚠️ Contains '@'")
        if text.count('-') > 3 or text.count('_') > 3: heur_score = max(heur_score,0.5); reasons.append("⚠️ Many special characters")
        if len(text) > 75: heur_score = max(heur_score,0.55); reasons.append("⚠️ URL unusually long")

        return min(1.0, heur_score), reasons, trusted_found

    def detect(self, input_text, threshold=None):
        if isinstance(threshold, dict):
            threshold = threshold.get("threshold", DEFAULT_THRESHOLD)
        try:
            threshold_use = float(threshold)
        except:
            threshold_use = DEFAULT_THRESHOLD

        text = input_text.strip()
        is_url = re.match(r"^(https?:\/\/|www\.)", text) or "." in text
        feats = np.array(extract_features_from_url(text if is_url else "textinput.local"), dtype=float)

        domain = ""
        try:
            parsed = urlparse(text if is_url else "")
            domain = (parsed.hostname or "").lower() if parsed.hostname else ""
        except:
            domain = ""

        ml_prob, per_model = self.ml.predict_proba(feats)
        heur_score, heur_reasons, trusted_found = self._heuristic_score(text, domain)

        ml_weight = self.ml_weight
        if len(text) > 100 or heur_score > 0.7: ml_weight = 0.4

        final_score = ml_prob * ml_weight + heur_score * (1 - ml_weight)
        if trusted_found: final_score *= 0.3

        verdict = "phishing" if final_score>=threshold_use else "suspicious" if final_score>=threshold_use*0.6 else "legitimate"
        reasons = heur_reasons + [f"ML: probability {ml_prob:.2f}"]

        return {
            "input": text,
            "domain": domain or "(file content)" if not is_url else domain,
            "type": "url" if is_url else "file",
            "ml_probability": round(ml_prob,4),
            "heuristic_score": round(heur_score,4),
            "final_score": round(final_score,4),
            "verdict": verdict,
            "threshold": threshold_use,
            "trusted": trusted_found,
            "reasons": reasons,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "per_model": per_model
        }

detector = PhishingDetector(ml_predictor)

# ------------------------------
# Convenience functions
# ------------------------------
def detect_phishing(url, threshold=None):
    return detector.detect(url, threshold)

def retrain_model(samples=3000):
    return ml_predictor.retrain(samples)

# ------------------------------
# Train from CSV
# ------------------------------
def train_from_csv(csv_path, target_col="label"):
    """
    Train the ML ensemble from a CSV file.
    Assumes features columns match FEATURE_NAMES and target_col is the label.
    """
    import joblib

    if not os.path.exists(csv_path):
        logging.error(f"CSV file not found: {csv_path}")
        return False

    df = pd.read_csv(csv_path)
    if target_col not in df.columns:
        logging.error(f"Target column '{target_col}' not in CSV")
        return False

    X = df[FEATURE_NAMES].values
    y = df[target_col].values
    X, y = shuffle(X, y, random_state=1)

    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, stratify=y, random_state=1)
    estimators = ml_predictor._build_estimators()
    fitted = [(name, model.fit(X_train, y_train)) for name, model in estimators.items()]
    weights = [1, 1, 0.5, 2, 2.5, 2]

    ensemble = VotingClassifier(estimators=fitted, voting="soft", weights=weights, n_jobs=-1)
    ensemble.fit(X_train, y_train)
    joblib.dump(ensemble, MODEL_PATH)

    ml_predictor.model = ensemble
    logging.info(f"✅ ML Model trained from CSV and saved to {MODEL_PATH}")
    return True
