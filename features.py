# features.py — Advanced URL Feature Extraction for Phishing Detection (Revised)
import re
from urllib.parse import urlparse
from datetime import datetime
import math
import whois

# ===============================
# TRUSTED DOMAINS / SUSPICIOUS TOKENS
# ===============================
TRUSTED_DOMAINS = [
    "openai.com",
    "github.com",
    "python.org",
    "wikipedia.org",
    "example.com"
]

SUSPICIOUS_TOKENS = [
    "login", "verify", "update", "secure", "account", "password",
    "bank", "prize", "reward", "free", "click", "urgent", "confirm",
    "reset", "winner", "claim"
]

# ===============================
# FEATURE NAMES
# ===============================
FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "num_digits",
    "num_hyphens",
    "num_at_symbols",
    "num_question_marks",
    "num_equals",
    "num_percent",
    "num_underscores",
    "num_dots",
    "has_ip_address",
    "num_suspicious_tokens",
    "is_https",
    "num_non_ascii",
    "non_ascii_ratio",
    "num_zero_width_chars",
    "zero_width_ratio",
    "has_punycode",
    "num_subdomains",
    "domain_entropy",
    "tld_risk_score",
    "domain_age_days",
]

# ===============================
# REGEX PATTERNS
# ===============================
ZERO_WIDTH_RE = re.compile(r"[\u200B\u200C\u200D\uFEFF]")
NON_ASCII_RE = re.compile(r"[^\x00-\x7F]")
PUNYCODE_RE = re.compile(r"xn--", re.IGNORECASE)
IP_RE = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

# Optional TLD risk scores
TLD_RISK_SCORES = {
    "com": 0.1,
    "org": 0.05,
    "net": 0.1,
    "xyz": 0.9,
    "top": 0.8,
    "club": 0.7,
    "info": 0.5,
    "online": 0.6,
}

# ===============================
# UTILITY FUNCTIONS
# ===============================
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c)/len(s) for c in set(s)]
    return -sum(p*math.log2(p) for p in probs)

def count_subdomains(hostname: str) -> int:
    if not hostname:
        return 0
    parts = hostname.split('.')
    return max(len(parts) - 2, 0)

def get_tld_risk(hostname: str) -> float:
    if not hostname or '.' not in hostname:
        return 0.0
    tld = hostname.split('.')[-1].lower()
    return TLD_RISK_SCORES.get(tld, 0.2)

def get_domain_age_days(hostname: str) -> float:
    """Return domain age in days. If unavailable, return 0."""
    if not hostname:
        return 0.0
    try:
        parts = hostname.split('.')
        domain = '.'.join(parts[-2:]) if len(parts) > 1 else hostname
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            return max((datetime.utcnow() - creation_date).days, 0.0)
    except:
        pass
    return 0.0

# ===============================
# FEATURE EXTRACTION FUNCTION
# ===============================
def extract_features_from_url(url: str) -> list:
    """Extract 24 features from URL for phishing detection."""
    features = []
    url = (url or "").strip()
    features.append(len(url))  # url_length

    # Parse URL safely
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        features.extend([len(hostname), len(path), len(query)])
    except:
        hostname, path, query = "", "", ""
        features.extend([0, 0, 0])

    # Character counts
    features.append(sum(c.isdigit() for c in url))  # num_digits
    features.append(url.count('-'))                  # num_hyphens
    features.append(url.count('@'))                  # num_at_symbols
    features.append(url.count('?'))                  # num_question_marks
    features.append(url.count('='))                  # num_equals
    features.append(url.count('%'))                  # num_percent
    features.append(url.count('_'))                  # num_underscores
    features.append(url.count('.'))                  # num_dots

    # IP address check
    features.append(1 if IP_RE.match(hostname) else 0)

    # Suspicious tokens
    features.append(sum(1 for t in SUSPICIOUS_TOKENS if t in url.lower()))

    # HTTPS
    features.append(1 if url.lower().startswith("https://") else 0)

    # Non-ASCII & zero-width
    non_ascii_count = len(NON_ASCII_RE.findall(url))
    features.append(non_ascii_count)
    features.append(non_ascii_count / max(len(url), 1))
    zero_width_count = len(ZERO_WIDTH_RE.findall(url))
    features.append(zero_width_count)
    features.append(zero_width_count / max(len(url), 1))

    # Punycode
    features.append(1 if PUNYCODE_RE.search(hostname) else 0)

    # Subdomains, entropy, TLD risk, domain age
    features.append(count_subdomains(hostname))
    features.append(shannon_entropy(hostname))
    features.append(get_tld_risk(hostname))
    features.append(get_domain_age_days(hostname))

    # Ensure all features are numeric
    features = [float(f) if f is not None else 0.0 for f in features]

    return features
