# file_scanner.py
import os
import re
from io import BytesIO
from bs4 import BeautifulSoup

try:
    from PyPDF2 import PdfReader
except Exception:
    PdfReader = None

try:
    from docx import Document
except Exception:
    Document = None

ALLOWED_EXT = {".pdf", ".docx", ".txt", ".html", ".htm", ".eml"}


def allowed_file(filename: str) -> bool:
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXT


def extract_text_and_links(file_bytes: bytes, filename: str):
    text = ""
    urls = []
    ext = os.path.splitext(filename)[1].lower()
    try:
        if ext == ".pdf" and PdfReader is not None:
            reader = PdfReader(BytesIO(file_bytes))
            for page in reader.pages:
                try:
                    text += page.extract_text() or ""
                except Exception:
                    continue
            urls = re.findall(r"https?://[^\s)'\"]+", text)
        elif ext == ".docx" and Document is not None:
            doc = Document(BytesIO(file_bytes))
            text = "\n".join([p.text for p in doc.paragraphs])
            urls = re.findall(r"https?://[^\s)'\"]+", text)
        elif ext in (".html", ".htm"):
            soup = BeautifulSoup(file_bytes, "html.parser")
            text = soup.get_text(separator="\n")
            urls = [a["href"] for a in soup.find_all("a", href=True) if a["href"].startswith("http")]
        elif ext == ".txt" or ext == ".eml":
            text = file_bytes.decode("utf-8", errors="ignore")
            urls = re.findall(r"https?://[^\s)'\"]+", text)
        else:
            text = file_bytes.decode("utf-8", errors="ignore")
            urls = re.findall(r"https?://[^\s)'\"]+", text)
    except Exception:
        pass

    urls = list(dict.fromkeys(urls))
    return text.strip(), urls


def scan_file(file_bytes: bytes, filename: str, settings: dict = None, threshold: float = None):
    from predictor import detect_phishing
    text, urls = extract_text_and_links(file_bytes, filename)
    results = []
    if urls:
        for u in urls:
            results.append(detect_phishing(u, settings=settings, threshold=threshold))
    elif text:
        results.append(detect_phishing(text[:4000], settings=settings, threshold=threshold))
    suspicious = [r for r in results if r.get("verdict") == "phishing"]
    return {
        "filename": filename,
        "url_count": len(urls),
        "phishing_detected": len(suspicious),
        "total_scanned": len(results),
        "results": results,
        "verdict": "phishing" if suspicious else "legitimate"
    }
