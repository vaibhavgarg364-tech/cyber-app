from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
import logging
import os
import socket
import tempfile
import time
import ssl
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, File, Form, UploadFile
from pydantic import BaseModel, EmailStr, Field, HttpUrl
import requests
import numpy as np

try:
    from google_play_scraper import search, app as play_app
except ImportError:
    search = None
    play_app = None

from config import firebase_store, load_json_file, settings
from routes import deepfake_pipeline
from routes.deepfake_pipeline import DeepfakeDetector
from routes.utils import (
    domain_from_url,
    iso_now,
    now_ts,
    safe_request_json,
    sha_key,
    url_scam_signals,
    download_media_from_url,
    sanitize_for_json,
)

router = APIRouter(tags=["detectors"])
logger = logging.getLogger("veyron-backend.detectors")
logger.info(
    "[Deepfake Route Startup] route_file=%s pipeline_file=%s detector_api=%s detector_init=%s tasks_active=%s import_error=%s",
    __file__,
    getattr(deepfake_pipeline, "__file__", "unknown"),
    deepfake_pipeline.mp_startup_info.get("api"),
    deepfake_pipeline.mp_startup_info.get("detector_init"),
    deepfake_pipeline.mp_startup_info.get("api") == "tasks_vision",
    deepfake_pipeline.mp_startup_info.get("import_error"),
)

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
GOV_APPS_DB = load_json_file(DATA_DIR / "gov_apps.json")
CACHE_TTL_SECONDS = 24 * 60 * 60
BREACH_DIRECTORY_URL = "https://breachdirectory.org/api/v1/breach"
XPOSEDORNOT_ANALYTICS_URL = "https://api.xposedornot.com/v1/breach-analytics"
VIRUSTOTAL_URL_SCAN_URL = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/{analysis_id}"
DISPOSABLE_EMAIL_DOMAINS = {
    "mailinator.com",
    "temp-mail.org",
    "10minutemail.com",
    "guerrillamail.com",
    "yopmail.com",
    "sharklasers.com",
    "getnada.com",
}

LOCAL_CACHE: Dict[str, Dict[str, Any]] = {}
DEEPFAKE_ENGINE: Optional["DeepfakeDetector"] = None
IO_POOL = ThreadPoolExecutor(max_workers=6)


class EmailCheckRequest(BaseModel):
    email: EmailStr


class LinkScanRequest(BaseModel):
    url: str


class AppCheckRequest(BaseModel):
    appName: str = Field(min_length=2, max_length=120)
    packageName: Optional[str] = None


class DeepfakeCheckRequest(BaseModel):
    mediaUrl: HttpUrl


def _normalize_deepfake_verdict_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    # Honest pipeline directly outputs well-calibrated verdicts. Just ensure all required frontend fields exist.
    payload.setdefault("verdict", "INSUFFICIENT EVIDENCE")
    payload.setdefault("verdict_color", "yellow")
    payload.setdefault("legacy_verdict", "unverified")
    
    conf = float(payload.get("confidence", payload.get("confidenceScore", 0.0)))
    payload["confidence"] = round(conf, 4)
    payload["confidenceScore"] = round(conf, 4)
    payload["confidencePercent"] = int(conf * 100)
    payload["confidence_percent"] = int(conf * 100)
    
    if "verdict_reason" not in payload:
        payload["verdict_reason"] = "Signals conflict or confidence is insufficient for a reliable determination."
        
    # FINAL AUDIT (Requirement 5): Ensure all native types
    sanitized = sanitize_for_json(payload)
    return sanitized


def _deepfake_route_debug(extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    detector = (
        "mediapipe_tasks_active"
        if deepfake_pipeline.mp_startup_info.get("api") == "tasks_vision"
        and deepfake_pipeline.mp_startup_info.get("detector_init")
        else "mediapipe_inactive"
    )
    payload = {
        "debug_detector": detector,
        "debug_route": "backend.routes.detectors.detect_deepfake",
        "debug_route_module": __file__,
        "debug_pipeline_module": getattr(deepfake_pipeline, "__file__", "unknown"),
        "debug_mediapipe_api": deepfake_pipeline.mp_startup_info.get("api"),
        "debug_mediapipe_initialized": deepfake_pipeline.mp_startup_info.get("detector_init", False),
        "debug_mediapipe_import_error": deepfake_pipeline.mp_startup_info.get("import_error"),
        "runtime_version": "ensemble_weight_patch_live",
    }
    if extra:
        payload.update(extra)
    return payload


def _deepfake_engine() -> DeepfakeDetector:
    global DEEPFAKE_ENGINE
    if DEEPFAKE_ENGINE is None:
        DEEPFAKE_ENGINE = DeepfakeDetector()
    return DEEPFAKE_ENGINE


def detect_deepfake_file(file_path: str) -> Dict[str, Any]:
    logger.info(
        "[Deepfake Runtime Path] detect_deepfake_file file=%s engine_class=%s pipeline_file=%s",
        file_path,
        DeepfakeDetector,
        getattr(deepfake_pipeline, "__file__", "unknown"),
    )
    return _deepfake_engine().detect_deepfake(file_path)


def _cache_get(key: str) -> Optional[Dict[str, Any]]:
    value = LOCAL_CACHE.get(key)
    if value and (now_ts() - value["timestamp"] <= CACHE_TTL_SECONDS):
        return value["data"]
    if firebase_store.enabled:
        doc = firebase_store.get_document("scan_cache", key)
        if doc and now_ts() - int(doc.get("timestamp", 0)) <= CACHE_TTL_SECONDS:
            return doc.get("data")
    return None


def _cache_set(key: str, data: Dict[str, Any]) -> None:
    payload = {"timestamp": now_ts(), "data": data}
    LOCAL_CACHE[key] = payload
    if firebase_store.enabled:
        firebase_store.save_document("scan_cache", key, payload)


def _risk_score_from_breaches(count: int) -> int:
    return min(count * 25, 100)


def _breach_severity_weight(exposed_data: List[str]) -> int:
    lowered = {x.lower().strip() for x in exposed_data}
    high = {"password", "passwords", "security questions", "credit card", "aadhaar", "pan"}
    medium = {"phone numbers", "phone", "name", "address", "username"}
    if lowered & high:
        return 20
    if lowered & medium:
        return 10
    return 5


def _fetch_hibp(email: str) -> List[Dict[str, Any]]:
    if not settings.hibp_api_key:
        return []
    headers = {
        "hibp-api-key": settings.hibp_api_key,
        "user-agent": "veyron-backend",
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    data = safe_request_json("GET", url, headers=headers, timeout=8)
    if not isinstance(data, list):
        return []
    hits: List[Dict[str, Any]] = []
    for item in data[:10]:
        hits.append(
            {
                "service": item.get("Name", "Unknown"),
                "date": item.get("BreachDate", "Unknown"),
                "exposed_data": item.get("DataClasses", ["email"]),
                "severity": min(100, 35 + _breach_severity_weight(item.get("DataClasses", ["email"]))),
                "actions": ["Change password", "Enable 2FA"],
            }
        )
    return hits


def _list_value(value: Any, default: Optional[List[str]] = None) -> List[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, str) and value.strip():
        return [part.strip() for part in value.split(",") if part.strip()]
    return default or []


def _first_value(item: Dict[str, Any], keys: List[str], default: str) -> str:
    for key in keys:
        value = item.get(key)
        if value:
            return str(value)
    return default


def _normalize_leakcheck_item(item: Dict[str, Any]) -> Dict[str, Any]:
    service = item.get("name", "Unknown Source")
    date = item.get("date", "Unknown")
    return {
        "service": service,
        "name": service,
        "date": date,
        "exposed_data": ["email", "password"],
        "exposedData": ["email", "password"],
        "severity": min(100, 30 + _breach_severity_weight(["email", "password"])),
        "source": "LeakCheck",
        "actions": ["Change password immediately", "Enable 2FA"],
    }


def _fetch_leakcheck(email: str) -> tuple[List[Dict[str, Any]], Optional[str]]:
    try:
        response = requests.get(
            f"https://leakcheck.io/api/public?check={email}",
            headers={"user-agent": "veyron-backend"},
            timeout=8,
        )
        if response.status_code != 200:
            return [], None
        data = response.json()
        if not data.get("success"):
            return [], None
    except Exception as exc:
        logger.warning("LeakCheck lookup failed for domain=%s: %s", email.split("@")[-1], exc)
        return [], "Could not check breach sources at this time."

    sources = data.get("sources", [])
    if not isinstance(sources, list):
        return [], None
    return [_normalize_leakcheck_item(item) for item in sources[:10]], None


def _normalize_xposedornot_item(item: Dict[str, Any]) -> Dict[str, Any]:
    exposed_data = (
        _list_value(item.get("xposed_data").replace(";", ",") if isinstance(item.get("xposed_data"), str) else None)
        or _list_value(item.get("exposedData"))
        or ["email"]
    )
    service = _first_value(item, ["breachID", "breach", "name"], "External breach source")
    date = _first_value(item, ["breachedDate", "xposed_date", "date"], "Unknown")
    if "T" in date:
        date = date.split("T")[0]
    return {
        "service": service,
        "name": service,
        "date": date,
        "domain": item.get("domain", ""),
        "exposed_data": exposed_data,
        "exposedData": exposed_data,
        "severity": min(100, 28 + _breach_severity_weight(exposed_data)),
        "source": "XposedOrNot",
        "actions": ["Change password immediately", "Enable 2FA"],
    }


def _fetch_proxynova(email: str) -> List[Dict[str, Any]]:
    hits = []
    try:
        r = requests.get(f"https://api.proxynova.com/comb?query={email}", timeout=8)
        data = r.json()
        lines = data.get("lines", [])
        for line in lines:
            if ":" in line:
                em, pw = line.split(":", 1)
                if em.lower() == email.lower() and pw:
                    hits.append({
                        "service": "COMB (Compilation of Many Breaches)",
                        "name": "COMB",
                        "date": "Historical",
                        "exposed_data": ["email", "password"],
                        "exposedData": ["email", "password"],
                        "severity": 95,
                        "source": "ProxyNova",
                        "actions": ["Change password immediately (password exposed)"]
                    })
                    break # Just report COMB once
    except Exception as exc:
        logger.warning(f"Proxynova lookup failed for {email.split('@')[-1]}: {exc}")
    return hits


def _fetch_holehe(email: str) -> List[Dict[str, Any]]:
    hits = []
    import sys, subprocess
    try:
        holehe_bin = "holehe.exe" if os.name == "nt" else "holehe"
        holehe_path = os.path.join(os.path.dirname(sys.executable), holehe_bin)
        
        # Fallback to pure shell resolution if not found
        if not os.path.exists(holehe_path):
            holehe_path = "holehe"

        result = subprocess.run([holehe_path, email, "--only-used", "--no-color"], capture_output=True, text=True, timeout=20)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("[+]") and not line.startswith("[+] Email used"):
                domain = line.replace("[+]", "").strip()
                hits.append({
                    "service": domain,
                    "name": domain,
                    "date": "Active Account",
                    "exposed_data": ["Public Footprint"],
                    "exposedData": ["Public Footprint"],
                    "severity": 10,
                    "source": "Digital Footprint (OSINT)",
                    "actions": ["Verify privacy settings", "Ensure strong unique password"]
                })
    except Exception as e:
        logger.warning("Holehe OSINT lookup failed for domain=%s: %s", email.split("@")[-1], e)
    return hits


def _fetch_xposedornot(email: str) -> tuple[List[Dict[str, Any]], Optional[str]]:
    try:
        response = requests.get(
            f"https://api.xposedornot.com/v1/check-email/{email}",
            headers={"accept": "application/json", "user-agent": "veyron-backend"},
            timeout=8,
        )
        if response.status_code == 404:
            return [], None
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        logger.warning("XposedOrNot lookup failed for domain=%s: %s", email.split("@")[-1], exc)
        return [], "Could not check breach sources at this time."

    breach_names = data.get("breaches", [])
    if not isinstance(breach_names, list) or not breach_names:
        return [], None
        
    if breach_names and isinstance(breach_names[0], list):
        breach_names = breach_names[0]

    try:
        b_resp = requests.get("https://api.xposedornot.com/v1/breaches", headers={"accept": "application/json", "user-agent": "veyron-backend"}, timeout=12)
        b_resp.raise_for_status()
        catalog_data = b_resp.json()
        catalog = catalog_data.get("exposedBreaches", []) or catalog_data
    except Exception as exc:
        logger.warning("XposedOrNot catalog lookup failed: %s", exc)
        return [], "Could not fetch breach details at this time."
        
    catalog_dict = {str(b.get("breachID", "")).lower(): b for b in catalog if isinstance(b, dict)}
    
    details: List[Dict[str, Any]] = []
    for name in breach_names:
        if isinstance(name, str):
            match = catalog_dict.get(name.lower())
            if match:
                details.append(match)
            else:
                details.append({"breachID": name, "breachedDate": "Unknown", "exposedData": ["email"]})

    email_domain = email.split("@")[-1].lower()
    email_brand = email_domain.split(".")[0]

    def relevance(item: Dict[str, Any]) -> tuple[int, str]:
        breach_name = str(item.get("breachID", "")).lower()
        breach_domain = str(item.get("domain", "")).lower()
        if breach_domain.endswith(email_domain):
            return (0, breach_name)
        if email_brand and email_brand in breach_name:
            return (1, breach_name)
        return (2, breach_name)

    sorted_details = sorted(details, key=relevance)
    return [_normalize_xposedornot_item(item) for item in sorted_details[:10]], None


@router.post("/check-email")
def check_email(payload: EmailCheckRequest) -> Dict[str, Any]:
    logger.info("Email check requested for domain=%s", payload.email.split("@")[-1])
    key = f"email:{sha_key(payload.email.lower())}"
    cached = _cache_get(key)
    if cached:
        return cached

    try:
        hibp_f = IO_POOL.submit(_fetch_hibp, payload.email)
        ext_f = IO_POOL.submit(_fetch_leakcheck, payload.email)
        osint_f = IO_POOL.submit(_fetch_holehe, payload.email)
        xposed_f = IO_POOL.submit(_fetch_xposedornot, payload.email)
        proxy_f = IO_POOL.submit(_fetch_proxynova, payload.email)
        
        hibp_hits = hibp_f.result()
        osint_hits = osint_f.result()
        proxy_hits = proxy_f.result()
        
        leakcheck_hits, leakcheck_error = ext_f.result()
        xposed_hits, xposed_error = xposed_f.result()
        
        external_hits = list(leakcheck_hits) + list(xposed_hits) + list(proxy_hits)
    except Exception as exc:
        logger.exception("Email provider lookup failed for domain=%s: %s", payload.email.split("@")[-1], exc)
        hibp_hits = []
        external_hits = []
        osint_hits = []
        leakcheck_error = True
        xposed_error = True
    breaches = (hibp_hits + external_hits + osint_hits)[:20]
    domain = payload.email.split("@")[-1].lower()
    disposable = domain in DISPOSABLE_EMAIL_DOMAINS
    severity_boost = min(35, sum(int(b.get("severity", 20)) for b in breaches) // 8)
    score = min(100, _risk_score_from_breaches(len(breaches)) + severity_boost + (15 if disposable else 0))
    is_safe = len(breaches) == 0
    recommendations = (
        [
            "Change password immediately",
            "Enable 2FA on all accounts",
            "Monitor credit reports and account activity",
            "Beware of targeted phishing emails and calls",
        ]
        if breaches
        else ["Keep monitoring your email and use unique passwords"]
    )
    legacy_breaches = [
        {
            "name": b["service"],
            "date": b["date"],
            "exposedData": b.get("exposed_data", []),
            "victims": 0,
            "whatToDo": ", ".join(b.get("actions", [])) or "Change password",
        }
        for b in breaches
    ]
    eng_summary = "No matching records were found for this email in the configured breach sources."
    hi_summary = "कॉन्फ़िगर किए गए ब्रीच स्रोतों में इस ईमेल का कोई रिकॉर्ड नहीं मिला।"
    
    if breaches:
        eng_summary = f"Critical alert! This email was found in {len(breaches)} known data breach(es). Change affected passwords immediately and enable Two-Factor Authentication."
        hi_summary = f"गंभीर चेतावनी! यह ईमेल {len(breaches)} ज्ञात डेटा ब्रीच में पाया गया है। तुरंत पासवर्ड बदलें और टू-फैक्टर ऑथेंटिकेशन सक्षम करें।"
        
    response = {
        "email": payload.email,
        "breaches_found": len(breaches) > 0,
        "breaches": breaches,
        "breach_count": len(breaches),
        "is_safe": is_safe,
        "risk_score": score,
        "disposable_domain": disposable,
        "email_domain": domain,
        # Backward compatibility for current frontend
        "breachesFoundRaw": breaches,
        "breachesFound": legacy_breaches,
        "isSafe": is_safe,
        "riskScore": score,
        "recommendations": recommendations,
        "englishSummary": eng_summary,
        "hindiSummary": hi_summary,
    }
    if leakcheck_error and xposed_error and not hibp_hits:
        response["warning"] = "Some breach providers were temporarily unavailable. Results may be incomplete."
    if disposable:
        response.setdefault("recommendations", []).insert(0, "Disposable email detected: avoid using this email for sensitive accounts.")
    _cache_set(key, response)
    logger.info(
        "Email check complete for domain=%s isSafe=%s breaches=%s risk=%s",
        payload.email.split("@")[-1],
        response["is_safe"],
        response["breach_count"],
        response["risk_score"],
    )
    return response


def _domain_age_from_whois(domain: str) -> str:
    # Lightweight fallback heuristic without paid WHOIS dependency.
    if any(tld in domain for tld in [".xyz", ".top", ".click"]):
        return "Likely very new"
    return "Unknown"


def _check_domain_reachability(url: str) -> tuple[bool, Optional[str]]:
    try:
        parsed = requests.utils.urlparse(url)
        host = parsed.hostname
        if not host:
            return False, "URL hostname could not be parsed."
        try:
            socket.getaddrinfo(host, None)
        except OSError:
            return False, "Domain DNS lookup failed."

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            with socket.create_connection((host, port), timeout=4):
                pass
        except OSError:
            return False, "Domain could not be reached."
    except Exception as exc:
        return False, f"Domain validation failed: {exc}"
    return True, None


def _redirect_profile(url: str) -> tuple[List[str], Optional[str]]:
    try:
        response = requests.get(url, allow_redirects=True, timeout=8, headers={"user-agent": "veyron-backend"})
        chain = [r.url for r in response.history] + [response.url]
        if len(chain) > 6:
            return chain, "Long redirect chain detected."
        return chain, None
    except Exception as exc:
        return [], f"Redirect analysis failed: {exc}"


def _domain_entropy(domain: str) -> float:
    if not domain:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in domain:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(domain))
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * np.log2(p)
    return float(ent)


def _ssl_snapshot(url: str) -> tuple[Dict[str, Any], Optional[str]]:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return {"https": False, "cert_validity_days": None}, "URL is not HTTPS."
    host = parsed.hostname
    if not host:
        return {"https": True, "cert_validity_days": None}, "HTTPS hostname parse failed."
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        days_left = None
        if not_after:
            exp_ts = time.mktime(time.strptime(not_after, "%b %d %H:%M:%S %Y %Z"))
            days_left = int((exp_ts - time.time()) // 86400)
        return {"https": True, "cert_validity_days": days_left}, None
    except Exception as exc:
        return {"https": True, "cert_validity_days": None}, f"SSL check failed: {exc}"


def _link_recommendations(verdict: str) -> List[str]:
    if verdict == "dangerous":
        return [
            "Do not open this link or enter any personal information.",
            "If you already interacted with it, change affected passwords immediately.",
            "Report the URL to your browser, email provider, or cybercrime.gov.in.",
        ]
    if verdict == "suspicious":
        return [
            "Do not enter passwords, OTPs, UPI PINs, or card details.",
            "Verify the link from the official website or app before proceeding.",
            "Open it only in an isolated browser profile if absolutely necessary.",
        ]
    if verdict == "unknown":
        return [
            "Scan could not be completed because the security API is not configured or failed.",
            "Do not rely on this result until VirusTotal or Safe Browsing is working.",
            "Manually verify the domain from an official source before clicking.",
        ]
    return [
        "No malicious engines flagged this URL in the configured checks.",
        "Still verify login and payment pages before entering sensitive information.",
        "Use unique passwords and two-factor authentication.",
    ]


def _google_safe_browsing(url: str) -> tuple[Dict[str, Any], Optional[str]]:
    if not settings.safe_browsing_api_key:
        return {"matches": []}, "Google Safe Browsing API key is not configured."
    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={settings.safe_browsing_api_key}"
    )
    body = {
        "client": {"clientId": "veyron-backend", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = requests.post(endpoint, json=body, timeout=8)
        if response.status_code in {401, 403}:
            message = response.json().get("error", {}).get("message", "unauthorized")
            return {"matches": []}, f"Google Safe Browsing API error: {message}"
        response.raise_for_status()
        return response.json(), None
    except Exception as exc:
        logger.warning("Google Safe Browsing lookup failed for url=%s: %s", url, exc)
        return {"matches": []}, f"Google Safe Browsing request failed: {exc}"


def _empty_vt_stats() -> Dict[str, int]:
    return {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "timeout": 0,
    }


def _virustotal_url_check(url: str) -> tuple[Dict[str, Any], Optional[str]]:
    if not settings.virustotal_api_key:
        return {"stats": _empty_vt_stats(), "results": {}}, "VirusTotal API key is not configured."
    headers = {"x-apikey": settings.virustotal_api_key}
    try:
        submit_response = requests.post(
            VIRUSTOTAL_URL_SCAN_URL,
            headers=headers,
            data={"url": url},
            timeout=12,
        )
        if submit_response.status_code in {401, 403}:
            return {"stats": _empty_vt_stats(), "results": {}}, "VirusTotal API key is invalid or unauthorized."
        submit_response.raise_for_status()
        submit = submit_response.json()
    except Exception as exc:
        logger.warning("VirusTotal submit failed for url=%s: %s", url, exc)
        return {"stats": _empty_vt_stats(), "results": {}}, f"VirusTotal submit failed: {exc}"

    analysis_id = submit.get("data", {}).get("id")
    if not analysis_id:
        return {"stats": _empty_vt_stats(), "results": {}}, "VirusTotal did not return an analysis id."

    analysis: Dict[str, Any] = {}
    for attempt in range(3):
        try:
            analysis_response = requests.get(
                VIRUSTOTAL_ANALYSIS_URL.format(analysis_id=analysis_id),
                headers=headers,
                timeout=12,
            )
            if analysis_response.status_code in {401, 403}:
                return {"stats": _empty_vt_stats(), "results": {}}, "VirusTotal API key is invalid or unauthorized."
            analysis_response.raise_for_status()
            analysis = analysis_response.json()
        except Exception as exc:
            logger.warning("VirusTotal analysis failed for id=%s: %s", analysis_id, exc)
            return {"stats": _empty_vt_stats(), "results": {}}, f"VirusTotal analysis failed: {exc}"

        status = analysis.get("data", {}).get("attributes", {}).get("status")
        if status != "queued" or attempt == 2:
            break
        time.sleep(1)

    attributes = analysis.get("data", {}).get("attributes", {})
    stats = attributes.get("stats") or attributes.get("last_analysis_stats") or {}
    if not stats:
        return {"stats": _empty_vt_stats(), "results": {}}, "VirusTotal analysis did not include detection stats yet."
    normalized_stats = _empty_vt_stats()
    for key in normalized_stats:
        normalized_stats[key] = int(stats.get(key, 0) or 0)

    return {
        "analysis_id": analysis_id,
        "stats": normalized_stats,
        "results": attributes.get("results", {}),
        "status": attributes.get("status", "completed"),
    }, None


@router.post("/scan-link")
def scan_link(payload: LinkScanRequest) -> Dict[str, Any]:
    url = str(payload.url)
    logger.info("Link scan requested url=%s", url)

    # Normalize before ALL processing — backend is the source of truth.
    from routes.website_scanner import normalize_url
    canonical_url, _hostname = normalize_url(url)
    logger.info("Link scan normalized url=%s → canonical=%s", url, canonical_url)

    # Cache key uses canonical URL so equivalent inputs share one entry.
    key = f"url:v3:{sha_key(canonical_url)}"
    cached = _cache_get(key)
    if cached:
        return cached

    from routes.website_scanner import ResearchScanner
    scanner = ResearchScanner(canonical_url)
    # Store original input so the report can display it
    scanner.target_url = canonical_url
    response = scanner.execute_scan()
    # Attach the original raw input so the frontend can show both
    response["original_input"] = url

    if response.get("verdict") not in ("unknown", "SCAN_FAILED", "INSUFFICIENT_EVIDENCE"):
        _cache_set(key, response)
    logger.info("Link scan complete canonical=%s verdict=%s", canonical_url, response.get("verdict"))
    return response



def _find_app_record(app_name: str) -> Optional[Dict[str, Any]]:
    needle = app_name.strip().lower()
    for app in GOV_APPS_DB.get("apps", []):
        if needle in app["name"].lower() or app["name"].lower() in needle:
            return app
    return None


def _dangerous_combo(perms: List[str]) -> bool:
    current = {p.upper() for p in perms}
    needed = {"CAMERA", "RECORD_AUDIO", "READ_CONTACTS"}
    return needed.issubset(current)


def _check_app_play_store(app_name: str, package_name: Optional[str]) -> Optional[Dict[str, Any]]:
    if search is None or play_app is None:
        return None
    try:
        # Search by package name if we have it, else by app_name
        pkg_to_fetch = package_name.strip() if package_name else None
        
        if not pkg_to_fetch:
            results = search(app_name, lang="en", country="in", n_hits=1)
            if not results:
                return None
            pkg_to_fetch = results[0]["appId"]
            
        details = play_app(pkg_to_fetch, lang="en", country="in")
        return details
    except Exception as exc:
        logger.warning(f"Play Store lookup failed for {app_name}: {exc}")
        return None

@router.post("/check-app")
def check_app(payload: AppCheckRequest) -> Dict[str, Any]:
    # 1. Fallback / Official check first
    official_app = _find_app_record(payload.appName)
    
    # 2. Live Play Store check
    live_details = _check_app_play_store(payload.appName, payload.packageName)

    BRAND_DEVELOPERS: Dict[str, str] = {
        "whatsapp": "WhatsApp LLC",
        "instagram": "Instagram",
        "amazon": "Amazon Mobile LLC",
        "spotify": "Spotify AB",
        "netflix": "Netflix, Inc.",
        "facebook": "Meta Platforms, Inc.",
        "paytm": "One97 Communications Ltd",
        "phonepe": "PhonePe Private Limited",
        "google pay": "Google LLC",
        "gpay": "Google LLC",
    }

    score: float = 0.0
    installs: Optional[str] = None

    if not official_app and not live_details:
        return {
            "verdict": "suspicious",
            "appName": payload.appName,
            "officialPackage": "Unknown",
            "permissions": [],
            "risks": ["App not found in Play Store or trusted government database."],
            "officialAlternatives": GOV_APPS_DB.get("apps", [])[:3],
            "recommendation": "Install only from official publishers. Avoid sideloading APKs.",
            "englishSummary": "No official match found. The app may be unverified or dangerous.",
            "hindiSummary": "कोई आधिकारिक मिलान नहीं मिला। ऐप असत्यापित या खतरनाक हो सकता है।",
        }

    mismatch = False
    verdict: Literal["official", "fake", "suspicious"] = "official"
    risks = []
    permissions = []

    input_package = (payload.packageName or "").strip()

    if live_details:
        # Use live Play Store data
        app_name = live_details.get("title", payload.appName)
        official_package = live_details.get("appId", "")
        developer = live_details.get("developer", "Unknown")
        score = float(live_details.get("score") or 0.0)
        installs = live_details.get("installs")

        if official_app and input_package and input_package != official_app["officialPackage"]:
            mismatch = True

        # Trust heuristics
        installs_str = installs or ""
        high_installs = any(x in installs_str for x in ["10,000,000+", "100,000,000+", "1,000,000,000+"])
        is_trusted = (score > 3.5) or high_installs

        if not is_trusted and not official_app:
            verdict = "suspicious"
            risks.append(f"Low trust indicators: {installs_str or 'unknown'} installs, {score:.1f}/5 rating.")

        # Expanded impersonation detection for popular brands
        app_name_lower = app_name.lower()
        for brand, expected_dev in BRAND_DEVELOPERS.items():
            if brand in app_name_lower and expected_dev.lower() not in developer.lower():
                verdict = "fake"
                risks.append(
                    f"Impersonation risk: '{app_name}' appears to impersonate {brand.title()} "
                    f"but developer '{developer}' does not match the official developer '{expected_dev}'."
                )
                break

    else:
        # Fallback to local gov DB
        app_name = official_app["name"]
        official_package = official_app["officialPackage"]
        developer = "Official Government Source"
        if input_package and input_package != official_package:
            mismatch = True

        for perm in official_app.get("permissions", []):
            risk = "low"
            if perm in {"READ_SMS", "RECORD_AUDIO", "READ_CONTACTS"}:
                risk = "medium"
            permissions.append({
                "permission": perm,
                "isRequired": perm in official_app.get("requiredPermissions", []),
                "riskLevel": risk,
                "explanation": "Review whether this permission is necessary."
            })

    if mismatch:
        verdict = "fake"
        risks.append(f"Package name mismatch. Expected {official_package} but got {input_package}.")

    if _dangerous_combo([p.get("permission", "") for p in permissions]):
        verdict = "suspicious" if verdict == "official" else verdict
        risks.append("Dangerous permission combo detected: Camera + Microphone + Contacts.")

    eng_summary = "Looks official. Keep Play Protect enabled."
    hi_summary = "आधिकारिक लगता है। प्ले प्रोटेक्ट सक्षम रखें।"

    if verdict == "fake":
        eng_summary = "High risk of impersonation. Uninstall immediately and use the official app."
        hi_summary = "प्रतिरूपण का उच्च जोखिम। तुरंत अनइंस्टॉल करें और आधिकारिक ऐप का उपयोग करें।"
    elif verdict == "suspicious":
        eng_summary = "App shows suspicious indicators. Proceed with caution."
        hi_summary = "ऐप संदिग्ध संकेत दिखाता है। सावधानी से आगे बढ़ें।"

    response = {
        "verdict": verdict,
        "appName": app_name,
        "developer": developer,
        "officialPackage": official_package,
        "rating": score if live_details else None,
        "installs": installs if live_details else None,
        "permissions": permissions,
        "risks": risks or ["No major red flags detected."],
        "officialAlternatives": [
            {
                "name": official_app["name"],
                "packageName": official_app["officialPackage"],
                "playStoreLink": official_app["playStoreLink"],
            }
        ] if official_app else [],
        "recommendation": eng_summary,
        "englishSummary": eng_summary,
        "hindiSummary": hi_summary,
    }
    return response


@router.post("/detect-deepfake")
async def detect_deepfake(
    mediaUrl: Optional[str] = Form(default=None),
    file: Optional[UploadFile] = File(default=None),
) -> Dict[str, Any]:
    logger.info(
        "[Deepfake Upload] route_entered mediaUrl_present=%s filename=%s pipeline_file=%s detector_api=%s tasks_active=%s",
        bool(mediaUrl),
        getattr(file, "filename", None),
        getattr(deepfake_pipeline, "__file__", "unknown"),
        deepfake_pipeline.mp_startup_info.get("api"),
        deepfake_pipeline.mp_startup_info.get("api") == "tasks_vision",
    )
    if not mediaUrl and not file:
        return _normalize_deepfake_verdict_payload({
            **_deepfake_route_debug(),
            "verdict": "INSUFFICIENT EVIDENCE",
            "legacy_verdict": "unverified",
            "verdict_color": "yellow",
            "confidence_percent": 0,
            "verdict_reason": "Provide either mediaUrl or a media file.",
            "confidence": 0,
            "details": "Provide either mediaUrl or a media file.",
            "recommendations": ["Upload a media file or provide a direct URL."],
            "englishSummary": "You must provide either a media URL or a media file.",
            "hindiSummary": "आपको मीडिया URL या मीडिया फ़ाइल में से कोई एक देना आवश्यक है।",
        })

    temp_path = None
    source_name = "unknown"
    is_video = False

    try:
        if file is None and mediaUrl:
            source_name = str(mediaUrl)
            logger.info("Downloading media from URL: %s", source_name)
            temp_path, error_msg = download_media_from_url(source_name)
            if error_msg or not temp_path:
                return _normalize_deepfake_verdict_payload({
                    **_deepfake_route_debug({"debug_source_name": source_name}),
                    "mediaUrl": source_name,
                    "mediaType": "url",
                    "analysisMode": "url-download-failed",
                    "verdict": "INSUFFICIENT EVIDENCE",
                    "legacy_verdict": "unverified",
                    "verdict_color": "yellow",
                    "confidence_percent": 0,
                    "verdict_reason": f"Could not download media: {error_msg}",
                    "confidence": 0,
                    "details": error_msg,
                    "findings": [error_msg],
                    "recommendations": ["Upload the original file directly instead of using a URL."],
                    "englishSummary": "Failed to download media from the provided URL.",
                    "hindiSummary": "दिए गए URL से मीडिया डाउनलोड करने में विफल।",
                })
        else:
            source_name = file.filename or "uploaded-file"
            suffix = Path(source_name).suffix or ".jpg"
            blob = await file.read()
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
                temp_file.write(blob)
                temp_path = temp_file.name

        try:
            model_result = detect_deepfake_file(temp_path)
        except ValueError as ve:
            return _normalize_deepfake_verdict_payload({
                **_deepfake_route_debug({"debug_source_name": source_name, "debug_actual_exception": str(ve)}),
                "mediaUrl": source_name,
                "verdict": "INSUFFICIENT EVIDENCE",
                "legacy_verdict": "unverified",
                "verdict_color": "yellow",
                "confidence_percent": 0,
                "verdict_reason": str(ve),
                "confidence": 0,
                "details": str(ve),
                "findings": [str(ve)],
                "recommendations": ["Ensure video is under 120 seconds and 50MB."],
                "englishSummary": str(ve),
                "hindiSummary": "वीडियो का आकार या अवधि अनुमत सीमा से अधिक है।",
            })
            
        verdict = str(model_result.get("verdict", "INCONCLUSIVE"))
        confidence = int(model_result.get("confidencePercent", 0))
        is_video = "video_stats" in model_result
        debug_info = model_result.get("debug_info", {}) if isinstance(model_result.get("debug_info"), dict) else {}
        face_count = int(model_result.get("debug_face_count", debug_info.get("detection_count", 0) or 0))
        bboxes = model_result.get("debug_bboxes", debug_info.get("bbox_coordinates", []))
        confidences = model_result.get("debug_confidences", debug_info.get("confidence_values", []))
        content_type = model_result.get("debug_content_type")
        if not content_type and isinstance(model_result.get("details"), str) and "Content Type:" in model_result["details"]:
            content_type = model_result["details"].split("Content Type:", 1)[1].split(".", 1)[0].strip()
        mediapipe_branch = bool(debug_info.get("mediapipe_branch_executed"))
        
        logger.info(
            "[Deepfake Upload Result] source=%s is_video=%s verdict=%s calibration_confidence=%s assessment=%s "
            "content_type=%s face_count=%s bboxes=%s confidences=%s mediapipe_branch_executed=%s detector=%s pipeline_file=%s",
            source_name,
            is_video,
            verdict,
            confidence,
            model_result.get("assessment"),
            content_type,
            face_count,
            bboxes,
            confidences,
            mediapipe_branch,
            model_result.get("debug_detector"),
            getattr(deepfake_pipeline, "__file__", "unknown"),
        )
        
        recs = [
            "Reverse-search keyframes before sharing.",
            "Verify using an official source before believing or forwarding.",
            "Report harmful content to the platform and to cyber authorities.",
        ]
        
        return _normalize_deepfake_verdict_payload({
            **_deepfake_route_debug({
                "debug_source_name": source_name,
                "debug_content_type": content_type,
                "debug_face_count": face_count,
                "debug_bboxes": bboxes,
                "debug_confidences": confidences,
                "debug_mediapipe_branch_executed": mediapipe_branch,
                "debug_inference_function": "DeepfakeDetector.detect_deepfake -> run_forensic_pipeline -> _detect_faces_mediapipe",
            }),
            **model_result,
            "mediaUrl": source_name,
            "mediaType": "video" if is_video else "image",
            "analysisMode": "hybrid-forensic-ml-video" if is_video else "hybrid-forensic-ml",
            "recommendations": recs,
            "englishSummary": (
                f"Multi-signal forensic screen completed for {'video' if is_video else 'image'}. "
                "This is an advisory signal—not court-grade proof; corroborate with independent checks."
            ),
            "hindiSummary": (
                f"बहु-संकेत फॉरेंसिक स्क्रीन पूर्ण ({'वीडियो' if is_video else 'छवि'})। यह सलाहकार परिणाम है—न्यायिक प्रमाण नहीं; स्वतंत्र जाँच से पुष्टि करें।"
            ),
        })

    except Exception as exc:
        logger.exception("Deepfake model failed for source=%s: %s", source_name, exc)
        return _normalize_deepfake_verdict_payload({
            **_deepfake_route_debug({"debug_source_name": source_name, "debug_actual_exception": repr(exc)}),
            "mediaUrl": source_name,
            "verdict": "INSUFFICIENT EVIDENCE",
            "legacy_verdict": "unverified",
            "verdict_color": "yellow",
            "confidence_percent": 0,
            "verdict_reason": f"Analysis could not be completed: {exc}",
            "confidence": 0,
            "details": f"Deepfake analysis failed: {exc}",
            "findings": [f"Could not complete local analysis for this file: {exc}"],
            "recommendations": ["Try uploading a clearer image."],
            "englishSummary": "Analysis could not be completed for this file. Try another image or format.",
            "hindiSummary": "इस फ़ाइल के लिए विश्लेषण पूरा नहीं हो सका। दूसरी छवि या प्रारूप आज़माएँ।",
        })
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception as e:
                logger.error(f"Failed to remove temp file {temp_path}: {e}")


@router.post("/extension/check-site")
def extension_check_site(payload: LinkScanRequest) -> Dict[str, Any]:
    scanned = scan_link(payload)
    verdict_map = {
        "safe": "safe",
        "suspicious": "warning",
        "uncertain": "warning",
        "dangerous": "danger",
        "malicious": "danger",
        "phishing": "danger",
    }
    raw_verdict = str(scanned.get("verdict") or "").strip().lower()
    v = verdict_map.get(raw_verdict, "warning")
    threat_level = 10
    if v == "warning":
        threat_level = 65
    elif v == "danger":
        threat_level = 95
    return {
        "verdict": v,
        "threatLevel": threat_level,
        "shouldBlock": v == "danger",
        "warningMessage": (
            "High risk site detected. Leave immediately."
            if v == "danger"
            else "Proceed with caution, verify domain."
        ),
        "actionButtons": ["Continue", "Leave Site"],
        "englishSummary": "If the verdict is dangerous, leave the site immediately.",
        "hindiSummary": "यदि निर्णय 'खतरनाक' हो, तो साइट तुरंत बंद करें।",
    }
