# features.py
import re
from urllib.parse import urlparse
import tldextract
import numpy as np

TRUSTED_DOMAINS = {"google.com", "github.com", "openai.com", "microsoft.com"}
SUSPICIOUS_TOKENS = [
    "login", "secure", "update", "verify", "account",
    "bank", "confirm", "reset", "billing", "signin",
    "password", "urgent", "ebay", "paypal", "free", "prize"
]

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "count_at",
    "count_dash",
    "count_dot",
    "count_digits",
    "count_slash",
    "suspicious_token",
    "has_ip",
    "is_trusted_domain"
]

def has_ip_address(hostname: str) -> bool:
    return bool(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", hostname))

def extract_features_from_url(url: str):
    if not url or not isinstance(url, str):
        return np.zeros(len(FEATURE_NAMES), dtype=float)

    candidate = url if re.match(r"^https?://", url) else "http://" + url
    parsed = urlparse(candidate)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    tx = tldextract.extract(hostname)
    domain = tx.domain + ("." + tx.suffix if tx.suffix else "")

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "count_at": url.count("@"),
        "count_dash": url.count("-"),
        "count_dot": url.count("."),
        "count_digits": sum(c.isdigit() for c in url),
        "count_slash": url.count("/"),
        "suspicious_token": int(any(tok in url.lower() for tok in SUSPICIOUS_TOKENS)),
        "has_ip": int(has_ip_address(hostname)),
        "is_trusted_domain": int(domain.lower() in TRUSTED_DOMAINS)
    }

    return np.array([float(features[n]) for n in FEATURE_NAMES], dtype=float)
