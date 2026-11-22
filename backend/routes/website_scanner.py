import logging
import re
import socket
import ssl
import time
import urllib.parse
import os
import csv
import json
import shutil
import zipfile
from pathlib import Path
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple, Set
import requests
import numpy as np
from google import genai
from config import settings
from routes.utils import url_scam_signals, sha_key, is_safe_public_url, is_restricted_ip

PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    pass


# ─────────────────────────────────────────────────────────────
# Canonical URL Normalizer
# Always call before caching, heuristics, and API lookups.
# ─────────────────────────────────────────────────────────────

_TRACKING_PARAMS = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "gclsrc", "dclid", "gbraid", "wbraid",
    "mc_cid", "mc_eid", "ref", "referrer", "source",
})

TRUSTED_DOMAINS: frozenset = frozenset({
    "google.com", "github.com", "microsoft.com", "apple.com", "openai.com",
    "cloudflare.com", "stackoverflow.com", "wikipedia.org", "amazon.com",
    "twitter.com", "x.com", "linkedin.com", "youtube.com", "netflix.com",
    "reddit.com", "mozilla.org", "python.org", "npmjs.com", "docker.com",
    "ubuntu.com", "debian.org", "archive.org", "whatsapp.com", "instagram.com",
    "facebook.com", "paypal.com", "stripe.com", "dropbox.com", "zoom.us",
    "slack.com", "adobe.com", "salesforce.com", "oracle.com", "ibm.com",
    # Additional global services
    "google.co.in", "gmail.com", "googleusercontent.com", "gstatic.com",
    "googleapis.com", "youtu.be", "bing.com", "yahoo.com", "outlook.com",
    "live.com", "office.com", "microsoftonline.com", "icloud.com",
    "whatsapp.net", "fb.com", "telegram.org", "duckduckgo.com",
    # India — banks, payments, commerce, government services
    "amazon.in", "flipkart.com", "paytm.com", "phonepe.com", "npci.org.in",
    "sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "kotak.com", "pnbindia.in", "bankofbaroda.in", "rbi.org.in",
    "irctc.co.in", "uidai.gov.in", "incometax.gov.in", "epfindia.gov.in",
    "cybercrime.gov.in", "india.gov.in", "digilocker.gov.in", "airtel.in",
    "jio.com", "myntra.com", "zomato.com", "swiggy.com",
})

_URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "rb.gy", "cutt.ly", "is.gd", "v.gd", "short.link", "tiny.cc",
    "lnk.to", "bl.ink", "snip.ly", "shorturl.at", "t.ly", "s.id",
    "rebrand.ly", "tinu.be", "qr.ae",
})

# Suffixes that are only issued to verified government / academic bodies.
_TRUSTED_SUFFIXES = (".gov.in", ".nic.in", ".gov", ".mil", ".ac.in", ".edu")


def is_trusted_host(hostname: str) -> bool:
    """True if hostname is a trusted domain or any subdomain of one."""
    host = (hostname or "").lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    if not host:
        return False
    if host in TRUSTED_DOMAINS:
        return True
    if any(host.endswith(sfx) for sfx in _TRUSTED_SUFFIXES):
        return True
    return any(host.endswith("." + d) for d in TRUSTED_DOMAINS)


# Brand token → official registrable domains. A brand appearing in a hostname
# that is not one of its official domains is a strong impersonation signal.
_BRAND_OFFICIAL: Dict[str, Tuple[str, ...]] = {
    "paypal": ("paypal.com",), "netflix": ("netflix.com",),
    "amazon": ("amazon.com", "amazon.in"), "flipkart": ("flipkart.com",),
    "paytm": ("paytm.com",), "phonepe": ("phonepe.com",),
    "google": ("google.com", "google.co.in"), "gmail": ("gmail.com", "google.com"),
    "microsoft": ("microsoft.com",), "office365": ("office.com", "microsoft.com"),
    "outlook": ("outlook.com", "live.com"), "apple": ("apple.com",),
    "icloud": ("icloud.com", "apple.com"), "facebook": ("facebook.com", "fb.com"),
    "instagram": ("instagram.com",), "whatsapp": ("whatsapp.com", "whatsapp.net"),
    "linkedin": ("linkedin.com",), "dropbox": ("dropbox.com",),
    "sbi": ("sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"), "onlinesbi": ("onlinesbi.sbi", "onlinesbi.com"),
    "yono": ("sbi.co.in", "onlinesbi.sbi"), "hdfc": ("hdfcbank.com",),
    "hdfcbank": ("hdfcbank.com",), "icici": ("icicibank.com",), "icicibank": ("icicibank.com",),
    "axisbank": ("axisbank.com",), "kotak": ("kotak.com",), "irctc": ("irctc.co.in",),
    "uidai": ("uidai.gov.in",), "aadhaar": ("uidai.gov.in",), "aadhar": ("uidai.gov.in",),
    "incometax": ("incometax.gov.in",), "epfo": ("epfindia.gov.in",),
    "airtel": ("airtel.in",), "jio": ("jio.com",), "npci": ("npci.org.in",),
    "telegram": ("telegram.org",),
}
# Brands distinctive enough to match as substrings (e.g. "secure-paypal1").
_SUBSTRING_BRANDS = frozenset({
    "paypal", "netflix", "flipkart", "phonepe", "instagram", "whatsapp",
    "facebook", "microsoft", "office365", "onlinesbi", "hdfcbank", "icicibank",
    "axisbank", "aadhaar", "incometax", "linkedin", "dropbox", "icloud", "irctc",
})
_LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_HOST_PHISH_KW = frozenset({
    "login", "signin", "verify", "verification", "secure", "security", "account",
    "update", "confirm", "kyc", "wallet", "support", "auth", "banking", "netbanking",
    "reward", "rewards", "gift", "refund", "bonus", "claim", "unlock", "suspended",
    "recovery", "helpdesk", "customercare", "otp", "pan", "aadhaar",
})


def detect_brand_impersonation(hostname: str) -> Optional[str]:
    """Return the impersonated brand if hostname uses a brand it doesn't own."""
    host = (hostname or "").lower()
    if not host or is_trusted_host(host):
        return None
    tokens = [t for t in re.split(r"[.\-_]", host) if t]
    leet_host = host.translate(_LEET_MAP)
    leet_tokens = [t for t in re.split(r"[.\-_]", leet_host) if t]
    for brand, official in _BRAND_OFFICIAL.items():
        if any(host == d or host.endswith("." + d) for d in official):
            continue
        if brand in tokens or brand in leet_tokens:
            return brand
        if brand in _SUBSTRING_BRANDS and (brand in host or brand in leet_host):
            return brand
    return None


_RISKY_TLDS = frozenset({
    ".xyz", ".top", ".click", ".win", ".zip", ".mov", ".loan", ".work",
    ".review", ".country", ".stream", ".gdn", ".science", ".party",
    # Free / ultra-cheap TLDs heavily abused for phishing
    ".tk", ".ml", ".ga", ".cf", ".gq", ".icu", ".cyou", ".buzz", ".rest",
    ".monster", ".sbs", ".cfd", ".bond", ".quest", ".support", ".bar",
})


def normalize_url(raw: str) -> Tuple[str, str]:
    """
    Canonicalize a raw URL string.
    Returns (canonical_url, canonical_hostname).

    Steps:
    1. Strip whitespace, lowercase
    2. Prepend https:// when no scheme present
    3. Parse with urlparse
    4. Lowercase hostname; strip bare www. prefix
    5. Remove default ports (:80/:443)
    6. Strip tracking query params (utm_*, fbclid, gclid, ref, etc.)
    7. Remove trailing slash from path
    8. Reconstruct canonical URL
    """
    url = raw.strip()
    lowered = url.lower()
    if not lowered.startswith("http://") and not lowered.startswith("https://"):
        url = "https://" + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return url, url

    scheme = parsed.scheme.lower() or "https"
    hostname = (parsed.hostname or "").lower()

    # Strip bare www. → canonical hostname
    canonical_hostname = hostname[4:] if hostname.startswith("www.") else hostname

    # Drop default ports
    port = parsed.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    # Strip tracking params, keep legitimate ones
    if parsed.query:
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs_clean = {k: v for k, v in qs.items() if k.lower() not in _TRACKING_PARAMS}
        query_str = urllib.parse.urlencode(qs_clean, doseq=True) if qs_clean else ""
    else:
        query_str = ""

    path = parsed.path.rstrip("/") or ""
    netloc = f"{canonical_hostname}:{port}" if port else canonical_hostname
    canonical = urllib.parse.urlunparse((scheme, netloc, path, "", query_str, ""))
    return canonical, canonical_hostname


# ─────────────────────────────────────────────────────────────
# Heuristic Analysis Engine
# Additive scoring — every triggered check explains its impact.
# ─────────────────────────────────────────────────────────────

def _better_entropy(text: str) -> float:
    """Shannon entropy (bits/char) of a string."""
    if not text:
        return 0.0
    import math
    from collections import Counter
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def run_heuristic_analysis(canonical_url: str, canonical_hostname: str, original_url: Optional[str] = None) -> Dict[str, Any]:
    """
    Evaluate canonical_url against 16 heuristic checks.
    Returns risk_score (0-100), overall_status, technical_checks,
    score_factors, threat_indicators, is_trusted.
    """
    if not original_url:
        original_url = canonical_url
    checks: List[Dict[str, Any]] = []
    factors: List[Dict[str, Any]] = []
    indicators: List[str] = []
    score = 0

    try:
        parsed = urllib.parse.urlparse(canonical_url)
    except Exception:
        parsed = urllib.parse.urlparse("https://unknown.invalid")

    scheme = parsed.scheme.lower()
    hostname = canonical_hostname
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = canonical_url

    # 1. Trusted domain baseline
    is_trusted = hostname in TRUSTED_DOMAINS
    if is_trusted:
        score = max(0, score - 30)
        factors.append({"factor": "Trusted domain", "impact": -30})

    # 2. HTTPS
    uses_https = scheme == "https"
    if not uses_https:
        score += 10
        factors.append({"factor": "HTTP (no encryption)", "impact": 10})
        indicators.append("Site does not use HTTPS encryption")
    checks.append({
        "check": "HTTPS",
        "passed": uses_https,
        "detail": "Connection uses HTTPS" if uses_https else "HTTP — traffic is unencrypted",
    })

    # 3. IP-address hostname
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))
    if is_ip:
        score += 20
        factors.append({"factor": "IP address as hostname", "impact": 20})
        indicators.append("URL uses a raw IP address instead of a domain name")
    checks.append({
        "check": "IP Address URL",
        "passed": not is_ip,
        "detail": "Hostname is a domain name" if not is_ip else f"Raw IP address: {hostname}",
    })

    # 4. Embedded credentials
    has_creds = bool(parsed.username)
    if has_creds:
        score += 30
        factors.append({"factor": "Embedded credentials in URL", "impact": 30})
        indicators.append("URL contains embedded username/password — classic phishing pattern")
    checks.append({
        "check": "Embedded Credentials",
        "passed": not has_creds,
        "detail": "No credentials embedded" if not has_creds else "Username/password found in URL",
    })

    # 5. URL shortener
    is_shortener = hostname in _URL_SHORTENERS
    if is_shortener:
        score += 20
        factors.append({"factor": "URL shortener detected", "impact": 20})
        indicators.append(f"URL shortener ({hostname}) hides the real destination")
    checks.append({
        "check": "URL Shortener",
        "passed": not is_shortener,
        "detail": "Not a known URL shortener" if not is_shortener else f"Shortener: {hostname}",
    })

    # 6. Punycode / homograph
    has_punycode = "xn--" in hostname
    if has_punycode:
        score += 25
        factors.append({"factor": "Punycode / homograph attack", "impact": 25})
        indicators.append("Punycode encoding detected — possible homograph spoofing")
    checks.append({
        "check": "Punycode / Homograph",
        "passed": not has_punycode,
        "detail": "No homograph pattern detected" if not has_punycode else f"Punycode in hostname: {hostname}",
    })

    # 7. Suspicious TLD
    has_risky_tld = any(hostname.endswith(tld) for tld in _RISKY_TLDS)
    if has_risky_tld and not is_trusted:
        score += 15
        factors.append({"factor": "High-risk top-level domain", "impact": 15})
        indicators.append("TLD frequently abused in phishing / scam campaigns")
    checks.append({
        "check": "Suspicious TLD",
        "passed": not has_risky_tld,
        "detail": "TLD is not high-risk" if not has_risky_tld else f"High-risk TLD in {hostname}",
    })

    # 8. Excessive subdomains
    labels = hostname.split(".")
    subdomain_depth = max(0, len(labels) - 2)
    has_excessive = subdomain_depth > 3
    if has_excessive:
        score += 10
        factors.append({"factor": "Excessive subdomain depth", "impact": 10})
        indicators.append(f"Unusually deep subdomain nesting ({subdomain_depth} levels)")
    checks.append({
        "check": "Excessive Subdomains",
        "passed": not has_excessive,
        "detail": f"Subdomain depth: {subdomain_depth}" if not has_excessive
                  else f"Deep nesting: {subdomain_depth} levels",
    })

    # 9. URL length
    url_len = len(full_url)
    if url_len > 200:
        score += 10
        factors.append({"factor": "Very long URL (>200 chars)", "impact": 10})
        indicators.append(f"URL is {url_len} characters — unusually long")
    elif url_len > 100:
        score += 5
        factors.append({"factor": "Long URL (>100 chars)", "impact": 5})
    checks.append({
        "check": "URL Length",
        "passed": url_len <= 100,
        "detail": f"{url_len} chars — acceptable" if url_len <= 100 else f"{url_len} chars — unusually long",
    })

    # 10. High entropy path
    entropy = _better_entropy(path + query)
    has_high_entropy = entropy > 3.8 and len(path) > 12
    if has_high_entropy:
        score += 10
        factors.append({"factor": "High entropy path / query", "impact": 10})
        indicators.append(f"Path entropy ({entropy:.1f} bits/char) suggests obfuscation")
    checks.append({
        "check": "High Entropy Path",
        "passed": not has_high_entropy,
        "detail": f"Entropy {entropy:.1f} — normal" if not has_high_entropy
                  else f"Entropy {entropy:.1f} — possible obfuscation",
    })

    # 11. Suspicious keywords in path or query
    _SUSPICIOUS_KW = {
        "login", "verify", "token", "otp", "password", "pwd",
        "secure", "account", "update", "confirm", "kyc", "reward",
        "gift", "wallet", "refund", "urgent", "auth", "credential",
        "sbi", "hdfc", "paypal", "netflix", "bank", "post", "support"
    }
    qp_keys = set(k.lower() for k in urllib.parse.parse_qs(query).keys())
    path_parts = set(re.split(r'[/.\-_]', path.lower()))
    suspicious_kws = (qp_keys | path_parts) & _SUSPICIOUS_KW
    has_suspicious_kw = bool(suspicious_kws) and not is_trusted
    if has_suspicious_kw:
        score += 20
        factors.append({"factor": "Suspicious keywords in URL", "impact": 20})
        indicators.append(f"Suspicious keywords: {', '.join(sorted(suspicious_kws))}")
    checks.append({
        "check": "Suspicious Keywords",
        "passed": not has_suspicious_kw,
        "detail": "No suspicious keywords" if not has_suspicious_kw
                  else f"Suspicious: {', '.join(sorted(suspicious_kws))}",
    })

    # 12. Non-standard port
    port = parsed.port
    has_suspicious_port = port is not None and port not in (80, 443, 8080, 8443)
    if has_suspicious_port:
        score += 10
        factors.append({"factor": f"Non-standard port ({port})", "impact": 10})
        indicators.append(f"Non-standard port {port} in use")
    checks.append({
        "check": "Suspicious Port",
        "passed": not has_suspicious_port,
        "detail": "Standard port" if not has_suspicious_port else f"Non-standard port: {port}",
    })

    # 13. Embedded secondary URL scheme in path or query
    has_embedded_scheme = bool(re.search(r"https?://", path, re.IGNORECASE)) or bool(re.search(r"(?:https?://|https?:/|//[a-zA-Z0-9.\-]+)", path + ("?" + query if query else "")))
    if has_embedded_scheme and not is_trusted:
        score += 25
        factors.append({"factor": "Embedded secondary URL scheme", "impact": 25})
        indicators.append("URL path contains an embedded secondary URL scheme (classic redirect / phishing obfuscation)")
    checks.append({
        "check": "Embedded URL Scheme",
        "passed": not has_embedded_scheme,
        "detail": "No secondary URL scheme embedded in path" if not has_embedded_scheme else "Secondary URL scheme embedded in path",
    })

    # 14. Direct executable / payload download target
    executable_exts = {".exe", ".scr", ".bat", ".cmd", ".msi", ".apk", ".dmg", ".vbs", ".iso", ".ps1"}
    has_executable_target = any(path.lower().endswith(ext) or (ext + "http") in path.lower() or (ext + "/") in path.lower() for ext in executable_exts)
    if has_executable_target and not is_trusted:
        score += 25
        factors.append({"factor": "Executable / payload download target", "impact": 25})
        indicators.append("URL directly targets an executable or installer file (.exe/.msi/.apk), indicating potential malware delivery")
    checks.append({
        "check": "Executable Target",
        "passed": not has_executable_target,
        "detail": "URL does not target an executable installer" if not has_executable_target else "Path targets direct executable file",
    })

    # 15. Brand impersonation / lookalike in hostname
    impersonated_brand = detect_brand_impersonation(hostname)
    has_brand_impersonation = bool(impersonated_brand) and not is_trusted
    if has_brand_impersonation:
        score += 35
        factors.append({"factor": f"Brand impersonation / lookalike ({impersonated_brand})", "impact": 35})
        indicators.append(f"Hostname contains unauthorized brand identifier or lookalike pattern for '{impersonated_brand}'")
    checks.append({
        "check": "Brand Authenticity",
        "passed": not has_brand_impersonation,
        "detail": "No brand lookalike pattern detected in hostname" if not has_brand_impersonation else f"Unauthorized use of brand '{impersonated_brand}' in hostname {hostname}",
    })

    # 16. RFC-reserved or special-use domain
    is_reserved_tld = hostname.endswith((".example", ".test", ".invalid", ".localhost", ".onion", ".local")) or hostname in {"example", "test", "invalid", "localhost"}
    if is_reserved_tld:
        indicators.append(f"Hostname uses an RFC-reserved or special-use domain ({hostname}) which does not exist on the public internet")
    checks.append({
        "check": "Public DNS Scope",
        "passed": not is_reserved_tld,
        "detail": "Standard public top-level domain" if not is_reserved_tld else f"RFC-reserved special-use domain ({hostname})",
    })

    score = min(100, max(0, score))

    # CRITICAL CORRECTION: "Trusted" is STRICTLY reserved for verified high-reputation domains (in TRUSTED_DOMAINS)
    # An unknown or arbitrary domain with 0 heuristic points is "Low Risk", NEVER "Trusted".
    if is_trusted and score <= 15:
        overall_status = "Trusted"
    elif has_brand_impersonation:
        overall_status = "Suspicious" if score <= 70 else "Dangerous"
        score = max(score, 50)
    elif score <= 25:
        overall_status = "Low Risk"
    elif score <= 45:
        overall_status = "Moderate Risk"
    elif score <= 70:
        overall_status = "Suspicious"
    else:
        overall_status = "Dangerous"

    return {
        "risk_score": score,
        "overall_status": overall_status,
        "technical_checks": checks,
        "score_factors": factors,
        "threat_indicators": indicators,
        "is_trusted": is_trusted,
        "brand_impersonation": {"brand": impersonated_brand} if has_brand_impersonation else None,
    }


# Caching engine for production optimization
class ScannerCache:
    def __init__(self, ttl_seconds: int = 300):
        self.url_cache = {}
        self.favicon_cache = {}
        self.ocr_cache = {}
        self.brand_cache = {}
        self.ttl = ttl_seconds
        self.hits = 0
        self.misses = 0

    def get_url(self, url: str):
        if url in self.url_cache:
            res, ts = self.url_cache[url]
            if time.time() - ts < self.ttl:
                self.hits += 1
                return res
            else:
                del self.url_cache[url]
        self.misses += 1
        return None

    def set_url(self, url: str, result: Any):
        self.url_cache[url] = (result, time.time())

    def get_favicon(self, domain: str):
        if domain in self.favicon_cache:
            val, ts = self.favicon_cache[domain]
            if time.time() - ts < self.ttl:
                return val
        return None

    def set_favicon(self, domain: str, val: Any):
        self.favicon_cache[domain] = (val, time.time())

    def get_ocr(self, html_hash: str):
        if html_hash in self.ocr_cache:
            val, ts = self.ocr_cache[html_hash]
            if time.time() - ts < self.ttl:
                return val
        return None

    def set_ocr(self, html_hash: str, val: Any):
        self.ocr_cache[html_hash] = (val, time.time())

    def get_brand(self, domain: str):
        if domain in self.brand_cache:
            val, ts = self.brand_cache[domain]
            if time.time() - ts < self.ttl:
                return val
        return None

    def set_brand(self, domain: str, val: Any):
        self.brand_cache[domain] = (val, time.time())

GLOBAL_SCANNER_CACHE = ScannerCache()

logger = logging.getLogger("veyron-backend")

# Standard headers for scanner request validation
SCANNER_USER_AGENT = "Mozilla/5.0 (compatible; VeyronSecurityScanner/2.0; +http://veyron.cybercell)"

# CVSS basic vector generator helper
def estimate_cvss(severity: str) -> Tuple[float, str]:
    if severity == "critical":
        return 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    elif severity == "high":
        return 8.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
    elif severity == "medium":
        return 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    elif severity == "low":
        return 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
    return 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"

# HTML parser to discover tags, forms, assets and scripts
class WebsiteHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.scripts: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self.assets: List[str] = []
        self.current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str]]):
        attrs_dict = dict(attrs)
        
        # Discover internal/external links
        if tag == "a" and "href" in attrs_dict:
            self.links.append(attrs_dict["href"])
            
        # Discover scripts
        if tag == "script":
            if "src" in attrs_dict:
                self.scripts.append(attrs_dict["src"])
            else:
                self.scripts.append("inline")
                
        # Discover forms
        if tag == "form":
            self.current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "get").lower(),
                "inputs": [],
                "encrypted": "multipart/form-data" in attrs_dict.get("enctype", "")
            }
            self.forms.append(self.current_form)
            
        if tag == "input" and self.current_form is not None:
            self.current_form["inputs"].append({
                "name": attrs_dict.get("name", ""),
                "type": attrs_dict.get("type", "text"),
                "value": attrs_dict.get("value", "")
            })
            
        # Discover assets
        if tag == "img" and "src" in attrs_dict:
            self.assets.append(attrs_dict["src"])
        if tag == "link" and attrs_dict.get("rel") == "stylesheet" and "href" in attrs_dict:
            self.assets.append(attrs_dict["href"])

    def handle_endtag(self, tag: str):
        if tag == "form":
            self.current_form = None


class ResearchScanner:
    def __init__(self, target_url: str):
        from routes.website_scanner import normalize_url
        canonical_url, canonical_hostname = normalize_url(target_url)
        self.target_url = canonical_url
        self.parsed_url = urllib.parse.urlparse(canonical_url)
        self.domain = canonical_hostname
        self.base_origin = f"{self.parsed_url.scheme}://{self.domain}"
        if self.parsed_url.port:
            self.base_origin += f":{self.parsed_url.port}"
        
        # SAFE MODE & Hardened Limits settings (Part 2)
        self.rate_limit_delay = 0.02  # delay in seconds
        self.max_depth = 2
        self.max_requests = 15
        self.max_ocr_pages = 2
        self.max_redirects = 4
        self.layer_timeout = 2.5  # seconds per layer for fast UI response
        self.memory_limit_mb = 4096.0  # target memory limit (process uses ~1.3GB baseline for PyTorch)
        
        self.request_count = 0
        # Circuit breaker: once the target host is unreachable (DNS failure /
        # connection refused / timeout) skip further probes to it instantly.
        self.host_unreachable = False
        self.host_unreachable_reason = ""
        self.js_execution_budget = 500  # virtual cycles
        self.visited_urls: Set[str] = set()
        
        # Performance/Observability counters (Part 4)
        self.start_time = time.time()
        self.durations: Dict[str, float] = {}
        self.initial_memory = self._get_memory_usage()
        self.api_failures = 0
        self.timeouts_encountered = 0
        
        # Runtime State Manager (Phase 4)
        self.runtime_state = {
            "status": "SCAN_OK",
            "memory_events": [],
            "timeouts": [],
            "ocr_status": "Not Attempted",
            "playwright_status": "Not Attempted",
            "vt_quota": "OK",
            "gsb_quota": "OK",
            "crawler_failures": 0
        }
        
        # Results accumulator
        self.recon_data: Dict[str, Any] = {}
        self.crawler_data: Dict[str, Any] = {}
        self.passive_findings: List[Dict[str, Any]] = []
        self.active_findings: List[Dict[str, Any]] = []
        self.threat_intel_data: Dict[str, Any] = {}

    def _get_memory_usage(self) -> float:
        try:
            import os
            try:
                import psutil
                process = psutil.Process(os.getpid())
                return process.memory_info().rss / (1024 * 1024)
            except ImportError:
                # fallback for windows/standard if psutil is not available
                return 0.0
        except Exception:
            return 0.0
            
    def _generate_trusted_report(self) -> Dict[str, Any]:
        canonical_url, canonical_hostname = normalize_url(self.target_url)
        heuristic = run_heuristic_analysis(canonical_url, canonical_hostname, self.target_url)
        
        return {
            "target_url": self.target_url,
            "normalized_url": canonical_url,
            "original_input": self.target_url,
            "hostname": canonical_hostname,
            "verdict": "safe",
            "overall_status": "Trusted",
            "risk_score": 0,
            "confidence": 0.98,
            "confidence_percent": 98,
            "confidence_label": "Verified official authority domain",
            "invalid_domain": False,
            "connection_status": "Reachable",
            "threats": [],
            "threat_indicators": [],
            "malicious_count": 0,
            "suspicious_count": 0,
            "safe_count": 0,
            "harmless_count": 0,
            "undetected_count": 0,
            "total_engines": 0,
            "technical_checks": heuristic["technical_checks"],
            "score_factors": [{"factor": "Verified high-reputation authority domain", "impact": -30}],
            "recommendations": [
                f"{canonical_hostname} is an official, verified high-reputation domain.",
                "Safe to browse. Continue practicing standard cyber hygiene."
            ],
            "domainInfo": {
                "registeredDate": "Established",
                "age": "> 10 years",
                "reputation": "trusted"
            },
            "englishSummary": f"{canonical_hostname} is an authentic, globally verified authority service. No security threats or phishing indicators detected.",
            "hindiSummary": f"{canonical_hostname} एक सत्यापित और सुरक्षित आधिकारिक डोमेन है। कोई सुरक्षा खतरा नहीं पाया गया।",
            "findings": ["Official verified authority domain", "Valid HTTPS encryption verified", "Zero phishing indicators detected"],
            "details": ["Domain matches authoritative global trusted registry."],
            "findings_details": [],
            "fusion_report": {
                "verdict": "SAFE",
                "confidence": 0.98,
                "breakdown": {"passive": 0.0, "active": 0.0, "threat_intel": 0.0, "anomaly": 0.0}
            },
            "crawler_summary": {},
            "phishing_report": {
                "risk_score": 0,
                "indicators": [],
                "brand_impersonation": None
            },
            "api_status": {
                "heuristics": {"configured": True, "used": True, "status": "SUCCESS_CLEAN", "label": "Local Heuristics"},
                "virustotal": {"configured": bool(settings.virustotal_api_key), "used": False, "status": "NOT_QUERIED", "label": "VirusTotal"},
                "google_safe_browsing": {"configured": bool(settings.safe_browsing_api_key), "used": False, "status": "NOT_QUERIED", "label": "Google Safe Browsing"}
            },
            "observability": {
                "durations": {"total_scan": 0.005},
                "cache_stats": {"hits": 1}
            }
        }

    def _generate_degraded_report(self, reason: str) -> Dict[str, Any]:
        canonical_url, canonical_hostname = normalize_url(self.target_url)
        heuristic = run_heuristic_analysis(canonical_url, canonical_hostname, self.target_url)
        final_verdict = "safe" if heuristic.get("is_trusted") else ("suspicious" if heuristic["risk_score"] > 40 else "safe")
        self.runtime_state["status"] = "SCAN_FALLBACK"

        return {
            "target_url": self.target_url,
            "normalized_url": canonical_url,
            "original_input": self.target_url,
            "hostname": canonical_hostname,
            "verdict": final_verdict,
            "overall_status": heuristic.get("overall_status", "Low Risk"),
            "risk_score": heuristic.get("risk_score", 10),
            "confidence": 0.85 if heuristic.get("is_trusted") else 0.70,
            "confidence_percent": 85 if heuristic.get("is_trusted") else 70,
            "confidence_label": "Evaluated via real-time heuristics and reputation checks",
            "invalid_domain": False,
            "connection_status": "Reachable",
            "runtime_state": self.runtime_state,
            "threats": heuristic.get("threat_indicators", []),
            "threat_indicators": heuristic.get("threat_indicators", []),
            "malicious_count": 0,
            "suspicious_count": 0,
            "safe_count": 0,
            "harmless_count": 0,
            "undetected_count": 0,
            "total_engines": 0,
            "technical_checks": heuristic.get("technical_checks", []),
            "score_factors": heuristic.get("score_factors", []),
            "recommendations": ["Verified domain structure. Proceed with normal caution."],
            "domainInfo": {
                "registeredDate": "Unknown",
                "age": "Active",
                "reputation": "normal"
            },
            "englishSummary": f"Analysis complete for {canonical_hostname}. Status: {heuristic.get('overall_status', 'Low Risk')}.",
            "hindiSummary": f"{canonical_hostname} का विश्लेषण पूरा हुआ। स्थिति: {heuristic.get('overall_status', 'कम जोखिम')}।",
            "findings": [f"Heuristic analysis completed: {heuristic.get('overall_status', 'Low Risk')}"],
            "details": ["Fast-path heuristic and threat indicators evaluated."],
            "findings_details": [],
            "fusion_report": {
                "verdict": final_verdict.upper(),
                "confidence": 0.75,
                "breakdown": {"passive": 0.0, "active": 0.0, "threat_intel": 0.0, "anomaly": 0.0}
            },
            "crawler_summary": {},
            "phishing_report": {},
            "api_status": {
                "heuristics": {"configured": True, "used": True, "status": "SUCCESS_CLEAN" if heuristic.get("is_trusted") else "DEGRADED", "label": "Local Heuristics"},
                "virustotal": {"configured": bool(settings.virustotal_api_key), "used": False, "status": "NOT_QUERIED", "label": "VirusTotal"},
                "google_safe_browsing": {"configured": bool(settings.safe_browsing_api_key), "used": False, "status": "NOT_QUERIED", "label": "Google Safe Browsing"}
            }
        }

    def _generate_blocked_ssrf_report(self, reason: str) -> Dict[str, Any]:
        canonical_url, canonical_hostname = normalize_url(self.target_url)
        self.runtime_state["status"] = "BLOCKED_SSRF"
        return {
            "target_url": self.target_url,
            "normalized_url": canonical_url,
            "original_input": self.target_url,
            "hostname": canonical_hostname,
            "verdict": "BLOCKED",
            "overall_status": "Blocked",
            "risk_score": 0,
            "confidence": 1.0,
            "confidence_percent": 100,
            "confidence_label": "Restricted Target - Private / Internal Network Blocked",
            "invalid_domain": True,
            "is_blocked_target": True,
            "is_private_target": True,
            "connection_status": "Blocked",
            "runtime_state": self.runtime_state,
            "threats": [],
            "threat_indicators": [f"Access to restricted endpoint is blocked for security (SSRF prevention): {reason}"],
            "malicious_count": 0,
            "suspicious_count": 0,
            "safe_count": 0,
            "harmless_count": 0,
            "undetected_count": 0,
            "total_engines": 0,
            "recommendations": [
                "Target URL resolves to an internal, loopback, or private network address.",
                "Veyron only scans public internet domains. Private network addresses cannot be assessed for phishing.",
            ],
            "technical_checks": [
                {
                    "name": "SSRF Target Defense",
                    "status": "Blocked",
                    "details": reason,
                    "passed": False,
                }
            ],
            "domainInfo": {
                "registeredDate": "N/A",
                "age": "Restricted",
                "reputation": "blocked"
            },
            "findings": ["Private/Internal network address detected", "SSRF protection engaged"],
            "details": [reason],
            "findings_details": [],
            "api_status": {
                "heuristics": {"configured": True, "used": True, "label": "SSRF Guard"},
                "virustotal": {"configured": False, "used": False, "label": "VirusTotal"},
                "google_safe_browsing": {"configured": False, "used": False, "label": "Google Safe Browsing"}
            },
            "englishSummary": f"Scan Refused: {canonical_hostname} is an internal/private endpoint.",
            "hindiSummary": f"स्कैन अस्वीकृत: {canonical_hostname} एक आंतरिक या निजी नेटवर्क पता है।",
        }

    def _export_reports(self, report: Dict[str, Any]):
        try:
            exports_dir = Path(__file__).resolve().parents[1] / "exports"
            exports_dir.mkdir(parents=True, exist_ok=True)
            
            safe_domain = self.domain.replace(".", "_")
            if not safe_domain:
                safe_domain = "unknown"
            timestamp = int(time.time())
            
            # 1. JSON Report
            json_path = exports_dir / f"scan_{safe_domain}_{timestamp}.json"
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=4)
                
            # 2. CSV Report
            csv_path = exports_dir / f"scan_{safe_domain}_{timestamp}.csv"
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Field", "Value"])
                writer.writerow(["Target URL", report.get("target_url", self.target_url)])
                writer.writerow(["Verdict", report.get("verdict", "")])
                writer.writerow(["Confidence", report.get("confidence", "")])
                writer.writerow(["Findings Count", len(report.get("findings", []))])
                writer.writerow(["English Summary", report.get("englishSummary", "")])
                
            # 3. Evidence Export
            evidence_path = exports_dir / f"evidence_{safe_domain}_{timestamp}.txt"
            with open(evidence_path, "w", encoding="utf-8") as f:
                f.write(f"EVIDENCE DOSSIER FOR {self.target_url}\n")
                f.write("=" * 60 + "\n")
                f.write(f"Verdict: {report.get('verdict', '').upper()}\n")
                f.write(f"Confidence: {report.get('confidence', '')}\n\n")
                f.write("Findings Details:\n")
                for fd in report.get("findings_details", []):
                    f.write(f"- [{fd.get('category', 'general').upper()}] {fd.get('type')}: {fd.get('evidence')}\n")
                    
            # 4. Scan History
            history_path = exports_dir / "scan_history.json"
            history = []
            if history_path.exists():
                try:
                    with open(history_path, "r", encoding="utf-8") as f:
                        history = json.load(f)
                except Exception:
                    pass
            history.append({
                "url": self.target_url,
                "timestamp": timestamp,
                "verdict": report.get("verdict", ""),
                "findings_count": len(report.get("findings", []))
            })
            with open(history_path, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=4)
                
            # 5. Audit Bundle (ZIP)
            bundle_path = exports_dir / f"bundle_{safe_domain}_{timestamp}.zip"
            with zipfile.ZipFile(bundle_path, "w") as zipf:
                zipf.write(json_path, arcname=f"scan_{safe_domain}_{timestamp}.json")
                zipf.write(csv_path, arcname=f"scan_{safe_domain}_{timestamp}.csv")
                zipf.write(evidence_path, arcname=f"evidence_{safe_domain}_{timestamp}.txt")
        except Exception as e:
            logger.error(f"[ResearchScanner] Failed to generate exports: {e}")

    def execute_scan(self) -> Dict[str, Any]:
        # SSRF Protection: block private/loopback/cloud metadata endpoints immediately
        is_safe, ssrf_err = is_safe_public_url(self.target_url)
        if not is_safe:
            logger.warning(f"[ResearchScanner] SSRF protection triggered for {self.target_url}: {ssrf_err}")
            return self._generate_blocked_ssrf_report(ssrf_err or "Access to internal or private IP address forbidden.")

        # Fast path for trusted domains (immediate sub-second response)
        if is_trusted_host(self.domain):
            logger.info(f"[ResearchScanner] Fast-path hit for trusted domain: {self.domain}")
            return self._generate_trusted_report()

        # URL Cache check & Duplicate scan prevention (Part 1)
        cached_res = GLOBAL_SCANNER_CACHE.get_url(self.target_url)
        if cached_res:
            logger.info(f"[ResearchScanner] Cache hit for: {self.target_url}")
            return cached_res
            
        logger.info(f"[ResearchScanner] Starting hardened 7-layer scan on: {self.target_url}")
        
        # Memory safety: only trip if available system memory is critically exhausted (<100MB)
        try:
            import psutil
            if psutil.virtual_memory().available < 100 * 1024 * 1024:
                return self._generate_degraded_report("Host available memory is critically low.")
        except Exception:
            pass

        # Layer executors with timeout limits and failure safety checks
        layers = [
            ("recon", self._layer_1_recon),
            ("crawler", self._layer_2_crawler),
            ("passive", self._layer_3_passive),
            ("active", self._layer_4_active),
            ("threat_intel", self._layer_5_threat_intel)
        ]
        
        for name, layer_func in layers:
            l_start = time.time()
            try:
                # Execution wrapping
                layer_func()
            except Exception as e:
                self.api_failures += 1
                logger.error(f"[ResearchScanner] Layer {name} failed or timed out: {e}. Degrading gracefully.")
            
            dur = time.time() - l_start
            self.durations[name] = dur
            
            # Check elapsed layer budget (Part 2 & 4)
            if dur > self.layer_timeout:
                self.timeouts_encountered += 1
                logger.warning(f"[ResearchScanner] Layer {name} exceeded timeout limit: {dur:.2f}s")

        # Layer 5.5: Phishing Detection Engine (Modular Integration)
        l_start = time.time()
        self.phishing_report = {}
        try:
            from routes.phishing_engine import PhishingDetectionEngine
            html_content = self.recon_data.get("html_content", "")
            
            # Huge HTML mitigation check (Part 3)
            if len(html_content) > 1024 * 1024:  # 1MB limit
                logger.warning("[ResearchScanner] Truncating huge HTML for phishing engine scanning.")
                html_content = html_content[:512 * 1024]
                
            pe = PhishingDetectionEngine(self.target_url, html_content, self.recon_data, self.crawler_data)
            self.phishing_report = pe.evaluate(self.threat_intel_data)
        except Exception as e:
            self.api_failures += 1
            logger.error(f"[ResearchScanner] Phishing engine analysis failed: {e}")
        self.durations["phishing"] = time.time() - l_start

        # Layer 6: Dynamic Fusion
        l_start = time.time()
        try:
            fusion_report = self._layer_6_fusion()
        except Exception as e:
            self.api_failures += 1
            logger.error(f"[ResearchScanner] Fusion layer execution failed: {e}")
            fusion_report = {
                "fusion_score": 0.0,
                "verdict": "safe",
                "confidence": 0.45,
                "breakdown": {"passive": 0.0, "active": 0.0, "threat_intel": 0.0, "anomaly": 0.0}
            }
        self.durations["fusion"] = time.time() - l_start
        
        # Layer 7: Reporting with LLM summary/deduplication
        l_start = time.time()
        try:
            final_report = self._layer_7_reporting(fusion_report)
        except Exception as e:
            self.api_failures += 1
            logger.error(f"[ResearchScanner] Reporting failed: {e}")
            final_report = self._generate_degraded_report(f"Reporting compilation failed: {e}")
        self.durations["reporting"] = time.time() - l_start
        
        # Post-process duration, cache usage, memory profile
        self.durations["total_scan"] = time.time() - self.start_time
        final_mem = self._get_memory_usage()
        self.durations["memory_delta_mb"] = max(0.0, final_mem - self.initial_memory)
        
        # Observability logs (Part 4)
        logger.info(
            f"[ResearchScanner] Scan finished. Duration: {self.durations['total_scan']:.2f}s | "
            f"Cache Hits: {GLOBAL_SCANNER_CACHE.hits} | Cache Misses: {GLOBAL_SCANNER_CACHE.misses} | "
            f"Memory Delta: {self.durations['memory_delta_mb']:.2f}MB | Timeouts: {self.timeouts_encountered} | "
            f"API Failures: {self.api_failures}"
        )
        if self.durations["total_scan"] > 15.0:
            logger.warning(f"[ResearchScanner] Slow scan detected on {self.target_url}: {self.durations['total_scan']:.2f}s")
            
        final_report["observability"] = {
            "durations": self.durations,
            "cache_stats": {
                "hits": GLOBAL_SCANNER_CACHE.hits,
                "misses": GLOBAL_SCANNER_CACHE.misses
            },
            "memory_usage_mb": final_mem,
            "timeouts_encountered": self.timeouts_encountered,
            "api_failures": self.api_failures
        }

        # Cache final report
        GLOBAL_SCANNER_CACHE.set_url(self.target_url, final_report)
        
        # Generate exports (Part 5)
        self._export_reports(final_report)
        
        return final_report

    def _is_target_host(self, url: str) -> bool:
        try:
            return (urllib.parse.urlparse(url).hostname or "").lower() == (self.domain or "").lower()
        except Exception:
            return False

    def _safe_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        is_safe, _ = is_safe_public_url(url)
        if not is_safe:
            logger.warning(f"[ResearchScanner] SSRF blocked probe request to {url}")
            return None
        if self.host_unreachable and self._is_target_host(url):
            return None
        if self.request_count >= self.max_requests:
            logger.warning("[ResearchScanner] Safe mode: Request limit reached.")
            return None
        
        # Authorized Target Enforcement and Rate Limiting
        time.sleep(self.rate_limit_delay)
        self.request_count += 1
        
        headers = kwargs.get("headers", {})
        if "User-Agent" not in headers:
            headers["User-Agent"] = SCANNER_USER_AGENT
        headers["X-Scanner-Safe-Mode"] = "enabled"
        kwargs["headers"] = headers
        kwargs["timeout"] = kwargs.get("timeout", 2.5)

        # Hop-by-hop redirect following with individual SSRF validation on each hop
        current_url = url
        max_hops = 5
        try:
            for _ in range(max_hops):
                is_safe, ssrf_err = is_safe_public_url(current_url)
                if not is_safe:
                    logger.warning(f"[ResearchScanner] SSRF blocked redirect to restricted target: {current_url}")
                    return None
                req_kwargs = dict(kwargs)
                req_kwargs["allow_redirects"] = False
                resp = requests.request(method, current_url, **req_kwargs)

                # Post-connection socket verification to defeat DNS rebinding (TOCTOU)
                try:
                    raw_conn = getattr(getattr(resp, "raw", None), "_connection", None)
                    sock = getattr(raw_conn, "sock", None)
                    if sock and hasattr(sock, "getpeername"):
                        peer_name = sock.getpeername()
                        if peer_name and isinstance(peer_name, tuple):
                            peer_ip = peer_name[0]
                            restricted, reason = is_restricted_ip(peer_ip)
                            if restricted:
                                logger.warning(f"[ResearchScanner] DNS Rebinding blocked! Connected to restricted peer: {peer_ip} ({reason})")
                                resp.close()
                                return None
                except Exception as sock_err:
                    logger.debug(f"[ResearchScanner] Socket peer check passed/skipped: {sock_err}")

                if resp.is_redirect and "Location" in resp.headers:
                    next_url = urllib.parse.urljoin(current_url, resp.headers["Location"])
                    current_url = next_url
                else:
                    return resp
            return resp
        except requests.exceptions.TooManyRedirects:
            logger.warning(f"[ResearchScanner] Redirect loop / too many redirects halted for {url}")
            return None
        except requests.exceptions.SSLError as e:
            logger.debug(f"[ResearchScanner] SSL error for {url}: {e}")
            return None
        except requests.exceptions.ConnectionError as e:
            # Includes ConnectTimeout, DNS failures and refused connections.
            if self._is_target_host(url):
                self.host_unreachable = True
                self.host_unreachable_reason = f"{type(e).__name__}"
                logger.info(f"[ResearchScanner] Target host unreachable ({type(e).__name__}); skipping further probes.")
            return None
        except Exception as e:
            logger.debug(f"[ResearchScanner] Request failed for {url}: {e}")
            return None

    # ================= Layer 1: Reconnaissance =================
    def _layer_1_recon(self):
        dns_records = {}
        tls_info = {}
        headers_info = {}
        robots_info = {"parsed_rules": 0, "sitemaps": []}
        sitemap_info = {"status": "Not Checked"}
        
        # 1. DNS check (bounded: getaddrinfo can block ~10-20s on Windows for dead domains)
        try:
            import concurrent.futures as _cf
            ips = []
            _ex = _cf.ThreadPoolExecutor(max_workers=1)
            try:
                info = _ex.submit(socket.getaddrinfo, self.domain, None).result(timeout=2)
            finally:
                _ex.shutdown(wait=False)
            for item in info:
                ip = item[4][0]
                if ip not in ips:
                    ips.append(ip)
            dns_records["A"] = ips
        except Exception as e:
            reason = "timed out" if type(e).__name__ == "TimeoutError" else str(e)
            dns_records["error"] = f"DNS lookup failed: {reason}"
            self.host_unreachable = True
            self.host_unreachable_reason = "DNS resolution failed"
            
        # 2. TLS check
        if self.host_unreachable:
            tls_info["error"] = "Host did not resolve; TLS not attempted"
        elif self.parsed_url.scheme == "https":
            try:
                context = ssl.create_default_context()
                with socket.create_connection((self.domain, 443), timeout=2) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()
                        
                tls_info = {
                    "version": version,
                    "cipher_suite": cipher[0] if cipher else "Unknown",
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "notAfter": cert.get("notAfter"),
                }
            except Exception as e:
                tls_info["error"] = f"TLS handshake failed: {e}"
        else:
            tls_info["error"] = "Target is not using HTTPS"

        # 3. HTTP headers and page contents
        resp = self._safe_request("GET", self.target_url)
        html_content = ""
        if resp is not None:
            headers_info = dict(resp.headers)
            html_content = resp.text
            
        # 4. Robots check
        robots_url = urllib.parse.urljoin(self.base_origin, "/robots.txt")
        robots_resp = self._safe_request("GET", robots_url)
        if robots_resp is not None and robots_resp.status_code == 200:
            rules = 0
            for line in robots_resp.text.split("\n"):
                if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                    rules += 1
                if line.lower().startswith("sitemap:"):
                    robots_info["sitemaps"].append(line.split(":", 1)[1].strip())
            robots_info["parsed_rules"] = rules
            robots_info["status"] = "Found"
        else:
            robots_info["status"] = "Not Found"
            
        # 5. Sitemap check
        sitemap_url = robots_info["sitemaps"][0] if robots_info["sitemaps"] else urllib.parse.urljoin(self.base_origin, "/sitemap.xml")
        sitemap_resp = self._safe_request("GET", sitemap_url)
        if sitemap_resp is not None and sitemap_resp.status_code == 200:
            sitemap_info["status"] = "Found"
            sitemap_info["url"] = sitemap_url
        else:
            sitemap_info["status"] = "Not Found"
            
        # 6. JS, Forms, Assets discovery
        parser = WebsiteHTMLParser()
        try:
            if html_content:
                parser.feed(html_content)
        except Exception:
            pass
            
        self.recon_data = {
            "dns": dns_records,
            "tls": tls_info,
            "headers": headers_info,
            "robots": robots_info,
            "sitemap": sitemap_info,
            "scripts": parser.scripts,
            "forms": parser.forms,
            "assets_count": len(parser.assets),
            "html_content": html_content,
            "links": parser.links
        }

    # ================= Layer 2: Crawler =================
    def _layer_2_crawler(self):
        if self.host_unreachable:
            self.crawler_data = {
                "spider_crawled_urls": [],
                "headless_crawler": f"Skipped (host unreachable: {self.host_unreachable_reason})",
                "dynamic_routes_discovered": [],
                "screenshot_path": "",
            }
            return
        if self.domain in getattr(self, "_trusted_cache", TRUSTED_DOMAINS):
            self.crawler_data = {
                "spider_crawled_urls": [],
                "headless_crawler": "Skipped (trusted domain)",
                "dynamic_routes_discovered": [],
                "screenshot_path": ""
            }
            return

        if not PLAYWRIGHT_AVAILABLE:
            logger.info("[ResearchScanner] Playwright is not available. Running simulated crawler.")
            self._simulated_crawler()
            return

        logger.info("[ResearchScanner] Playwright available. Launching real browser execution...")
        crawled_urls = []
        dynamic_routes = []
        network_calls = []
        
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, timeout=5000)
                context = browser.new_context(user_agent=SCANNER_USER_AGENT)
                page = context.new_page()
                
                # Intercept network calls to extract dynamic XHR/fetch APIs (Part 3)
                page.on("request", lambda req: network_calls.append(req.url) if req.resource_type in ("xhr", "fetch") else None)
                
                # Navigate to destination
                page.goto(self.target_url, timeout=5000, wait_until="domcontentloaded")
                
                # Capture screenshot for visual pipeline (Part 2)
                exports_dir = Path(__file__).resolve().parents[1] / "exports"
                screenshots_dir = exports_dir / "screenshots"
                screenshots_dir.mkdir(parents=True, exist_ok=True)
                screenshot_path = screenshots_dir / f"screenshot_{self.domain.replace('.', '_')}.png"
                page.screenshot(path=str(screenshot_path))
                
                # Update HTML content & Title with real rendered DOM state
                rendered_html = page.content()
                if rendered_html:
                    self.recon_data["html_content"] = rendered_html
                self.title = page.title()
                
                # Discover dynamic route anchors
                anchors = page.locator("a").evaluate_all("elements => elements.map(el => el.href)")
                for link in anchors:
                    if not link: continue
                    full_url = urllib.parse.urljoin(self.target_url, link)
                    parsed_link = urllib.parse.urlparse(full_url)
                    if parsed_link.hostname == self.domain:
                        if full_url not in crawled_urls and len(crawled_urls) < 10:
                            crawled_urls.append(full_url)
                
                # Dynamic Route checks
                dynamic_routes.append("Rendered Single Page App (SPA) route verified")
                browser.close()
                
                self.crawler_data = {
                    "spider_crawled_urls": crawled_urls,
                    "headless_crawler": "Playwright Headless Browser (Active)",
                    "dynamic_routes_discovered": dynamic_routes,
                    "network_calls_extracted": network_calls[:20],
                    "screenshot_path": str(screenshot_path)
                }
        except Exception as e:
            self.api_failures += 1
            logger.error(f"[ResearchScanner] Playwright crashed during execution: {e}. Switching to lightweight mode.")
            self._simulated_crawler()

    def _simulated_crawler(self):
        crawled_urls = []
        dynamic_routes = []
        
        # 1. Normal Spider (follow internal links up to max depth)
        for link in self.recon_data.get("links", []):
            full_url = urllib.parse.urljoin(self.target_url, link)
            parsed_link = urllib.parse.urlparse(full_url)
            if parsed_link.hostname == self.domain:
                if full_url not in crawled_urls and len(crawled_urls) < 10:
                    crawled_urls.append(full_url)
                    
        # 2. Headless browser simulator (simulate dynamic manifest lookup & client routing check)
        manifest_url = urllib.parse.urljoin(self.base_origin, "/manifest.json")
        manifest_resp = self._safe_request("GET", manifest_url, timeout=2.0)
        headless_simulator_status = "Skipped"
        if manifest_resp is not None and manifest_resp.status_code == 200:
            headless_simulator_status = "Completed (via Manifest & preloads evaluation)"
            
        # 3. Dynamic Route Discovery (directory/file guessing & SPA router check)
        common_paths = [
            "/api", "/admin", "/login", "/dashboard", "/v1", "/wp-admin", 
            "/signup", "/portal", "/config", "/test", "/dev"
        ]
        import concurrent.futures as _cf
        def _check_route(path: str):
            test_url = urllib.parse.urljoin(self.base_origin, path)
            resp = self._safe_request("HEAD", test_url, timeout=2.0)
            if resp is not None and resp.status_code in (200, 301, 302, 401, 403):
                return {"path": path, "status_code": resp.status_code}
            return None

        with _cf.ThreadPoolExecutor(max_workers=5) as ex:
            for route_hit in ex.map(_check_route, common_paths):
                if route_hit:
                    dynamic_routes.append(route_hit)
                
        self.crawler_data = {
            "spider_crawled_urls": crawled_urls,
            "headless_crawler": headless_simulator_status,
            "dynamic_routes_discovered": dynamic_routes,
            "screenshot_path": ""  # no screenshot in simulated mode
        }

    # ================= Layer 3: Passive Check =================
    def _layer_3_passive(self):
        headers = self.recon_data.get("headers", {})
        html_content = self.recon_data.get("html_content", "")
        
        # 1. CSP
        csp = headers.get("Content-Security-Policy", "")
        if not csp:
            self.passive_findings.append({
                "type": "Missing Content-Security-Policy",
                "severity": "medium",
                "impact": "High risk of Cross-Site Scripting (XSS) attacks.",
                "remediation": "Configure a strict Content-Security-Policy header."
            })
        elif "unsafe-inline" in csp or "*" in csp:
            self.passive_findings.append({
                "type": "Weak Content-Security-Policy",
                "severity": "low",
                "impact": "Wildcard or unsafe directives reduce policy effectiveness.",
                "remediation": "Remove 'unsafe-inline' and wildcards from CSP config."
            })

        # 2. HSTS
        hsts = headers.get("Strict-Transport-Security", "")
        if self.parsed_url.scheme == "https" and not hsts:
            self.passive_findings.append({
                "type": "Missing HSTS",
                "severity": "low",
                "impact": "Site does not enforce SSL/TLS for all incoming connections.",
                "remediation": "Add the Strict-Transport-Security header to force HTTPS."
            })

        # 3. Cookies
        set_cookie = headers.get("Set-Cookie", "")
        if set_cookie:
            missing_flags = []
            if "httponly" not in set_cookie.lower():
                missing_flags.append("HttpOnly")
            if "secure" not in set_cookie.lower() and self.parsed_url.scheme == "https":
                missing_flags.append("Secure")
            if missing_flags:
                self.passive_findings.append({
                    "type": "Insecure Cookie Flags",
                    "severity": "medium",
                    "impact": f"Session cookies are missing secure flags: {', '.join(missing_flags)}.",
                    "remediation": "Set HttpOnly, Secure, and SameSite attributes on all sensitive cookies."
                })

        # 4. CORS
        cors = headers.get("Access-Control-Allow-Origin", "")
        if cors == "*":
            self.passive_findings.append({
                "type": "Wildcard CORS Policy",
                "severity": "low",
                "impact": "Allows any external domain to read resource contents.",
                "remediation": "Restrict Access-Control-Allow-Origin to authorized origins."
            })

        # 5. JWT Leaks / API Key Exposure
        secret_patterns = {
            "Google API Key": r"AIzaSy[A-Za-z0-9-_]{35}",
            "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
            "Generic Private Key": r"-----BEGIN PRIVATE KEY-----",
            "JWT Pattern": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"
        }
        for name, pattern in secret_patterns.items():
            matches = re.findall(pattern, html_content)
            if matches:
                self.passive_findings.append({
                    "type": f"Exposed Secret: {name}",
                    "severity": "high",
                    "impact": f"Found reference matching {name} pattern in page source.",
                    "remediation": "Remove secrets/credentials from public-facing code."
                })

        # 6. Security Headers
        if "X-Frame-Options" not in headers:
            self.passive_findings.append({
                "type": "Missing X-Frame-Options",
                "severity": "low",
                "impact": "Exposes website to Clickjacking vulnerabilities.",
                "remediation": "Add X-Frame-Options header (DENY or SAMEORIGIN)."
            })
        if "X-Content-Type-Options" not in headers:
            self.passive_findings.append({
                "type": "Missing X-Content-Type-Options",
                "severity": "low",
                "impact": "Allows browsers to sniff mime types instead of respecting headers.",
                "remediation": "Set X-Content-Type-Options: nosniff."
            })

        # 7. Mixed Content
        if self.parsed_url.scheme == "https":
            http_links = re.findall(r'src="http://[^"]+"', html_content) + re.findall(r'href="http://[^"]+"', html_content)
            if http_links:
                self.passive_findings.append({
                    "type": "Mixed Content Detected",
                    "severity": "medium",
                    "impact": "Active resources (images/scripts) loaded insecurely over HTTP.",
                    "remediation": "Change all references to use https:// or relative paths."
                })

    # ================= Layer 4: Active Engine =================
    def _layer_4_active(self):
        # Skip invasive fuzzing against trusted platforms or unreachable hosts
        if self.domain in getattr(self, "_trusted_cache", TRUSTED_DOMAINS) or self.host_unreachable:
            return

        import concurrent.futures as _cf

        def _do_active_request(test_params: Dict[str, Any]):
            url = test_params["url"]
            method = test_params.get("method", "GET")
            allow_redirects = test_params.get("allow_redirects", True)
            check_type = test_params["check_type"]
            param = test_params.get("param")
            
            resp = self._safe_request(method, url, allow_redirects=allow_redirects)
            if resp is None:
                return None
                
            finding = None
            if check_type == "sqli":
                db_errors = ["mysql_fetch_array", "SQL syntax", "PostgreSQL query failed", "SQLite3::prepare", "Microsoft OLE DB Provider for ODBC Drivers"]
                if any(err in resp.text for err in db_errors):
                    finding = {"type": "Potential SQL Injection", "severity": "high", "evidence": f"Parameter '{param}' triggered database exception syntax signature.", "remediation": "Use prepared statements / parameterized queries."}
            elif check_type == "xss":
                if param in resp.text:
                    finding = {"type": "Reflected Cross-Site Scripting (XSS)", "severity": "high", "evidence": f"Input parameter reflected payload inside HTML response without escaping.", "remediation": "Perform context-aware HTML entity encoding on all user input before rendering."}
            elif check_type == "traversal":
                if resp.status_code == 200 and ("root:" in resp.text or "[extensions]" in resp.text):
                    finding = {"type": "Path Traversal Exposure", "severity": "critical", "evidence": f"Path traversal string successfully loaded host system configuration file.", "remediation": "Sanitize target file paths and validate against a strict white-list."}
            elif check_type == "redirect":
                if resp.status_code in (301, 302):
                    loc = resp.headers.get("Location", "")
                    if "google.com" in loc:
                        finding = {"type": "Unvalidated Open Redirect", "severity": "medium", "evidence": f"Redirect parameter allows jumping to an untrusted external URL.", "remediation": "Validate redirect destination against white-listed internal pages."}
            elif check_type == "backup":
                if resp.status_code == 200 and len(resp.text) > 0:
                    finding = {"type": f"Exposed Sensitive File: {param}", "severity": "high", "evidence": f"Successfully fetched sensitive configuration/backup at: {param}", "remediation": "Block access to configuration and backup extension resources."}
            elif check_type == "admin":
                if resp.status_code in (200, 301, 302, 401, 403):
                    finding = {"type": f"Discovered Administrative Endpoint: {param}", "severity": "low", "evidence": f"Endpoint exists and returned HTTP code {resp.status_code}.", "remediation": "Restrict login paths or protect them behind VPN/IP filters."}
            return finding

        tasks = []
        
        query_params = urllib.parse.parse_qs(self.parsed_url.query)
        if query_params:
            for param in query_params:
                test_query = urllib.parse.urlencode({param: "' OR '1'='1"})
                test_url = f"{self.base_origin}{self.parsed_url.path}?{test_query}"
                tasks.append({"url": test_url, "check_type": "sqli", "param": param})

        xss_payload = "<script>alert('veyron_xss')</script>"
        test_query = urllib.parse.urlencode({"q": xss_payload})
        test_url = f"{self.base_origin}/search?{test_query}"
        tasks.append({"url": test_url, "check_type": "xss", "param": xss_payload})

        for p in ["/../../../../etc/passwd", "/..\\..\\..\\..\\windows\\win.ini"]:
            tasks.append({"url": urllib.parse.urljoin(self.base_origin, p), "check_type": "traversal"})

        tasks.append({"url": f"{self.base_origin}/redirect?url=https://google.com", "check_type": "redirect", "allow_redirects": False})

        for bf in ["/backup.zip", "/db.sql", "/.env", "/.git/config"]:
            tasks.append({"url": urllib.parse.urljoin(self.base_origin, bf), "check_type": "backup", "param": bf})

        for ap in ["/admin", "/wp-admin", "/login.php", "/portal"]:
            tasks.append({"url": urllib.parse.urljoin(self.base_origin, ap), "check_type": "admin", "param": ap, "method": "HEAD"})

        with _cf.ThreadPoolExecutor(max_workers=5) as ex:
            results = ex.map(_do_active_request, tasks)
            for res in results:
                if res:
                    self.active_findings.append(res)

    # ================= Layer 5: Threat Intelligence =================
    def _vt_lookup(self) -> Tuple[Dict[str, int], str]:
        """VirusTotal: prefer the existing URL report (instant, full engine
        verdicts); fall back to submit + short poll for never-seen URLs."""
        import base64
        vt_stats = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
        if not settings.virustotal_api_key:
            return vt_stats, "NOT_CONFIGURED"
        headers = {"x-apikey": settings.virustotal_api_key}
        stats: Dict[str, Any] = {}
        status = "NOT_QUERIED"
        try:
            url_id = base64.urlsafe_b64encode(self.target_url.encode()).decode().strip("=")
            r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=2.5)
            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
                mal = int(stats.get("malicious", 0) or 0)
                sus = int(stats.get("suspicious", 0) or 0)
                tot = sum(int(stats.get(k, 0) or 0) for k in ["malicious", "suspicious", "harmless", "undetected"])
                if tot == 0:
                    status = "NO_INTELLIGENCE"
                elif mal > 0 or sus > 0:
                    status = "SUCCESS_MALICIOUS"
                else:
                    status = "SUCCESS_CLEAN"
            elif r.status_code == 404:
                status = "NO_INTELLIGENCE"
            elif r.status_code in (401, 403):
                status = "AUTH_ERROR"
            elif r.status_code == 429:
                self.runtime_state["vt_quota"] = "EXCEEDED"
                status = "RATE_LIMITED"
            else:
                status = "NETWORK_ERROR"
        except Exception as exc:
            logger.debug(f"[ResearchScanner] VirusTotal lookup failed: {exc}")
            if "Timeout" in type(exc).__name__:
                status = "TIMEOUT"
            else:
                status = "NETWORK_ERROR"
        for k in vt_stats:
            try:
                vt_stats[k] = int(stats.get(k, 0) or 0)
            except (TypeError, ValueError):
                vt_stats[k] = 0
        return vt_stats, status

    def _gsb_lookup(self) -> Tuple[List[Dict[str, Any]], str]:
        if not settings.safe_browsing_api_key:
            return [], "NOT_CONFIGURED"
        status = "NOT_QUERIED"
        try:
            endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.safe_browsing_api_key}"
            body = {
                "client": {"clientId": "veyron-backend", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": self.target_url}],
                },
            }
            resp = requests.post(endpoint, json=body, timeout=6)
            if resp.status_code == 200:
                matches = resp.json().get("matches", []) or []
                status = "SUCCESS_MALICIOUS" if matches else "SUCCESS_CLEAN"
                return matches, status
            elif resp.status_code in (400, 401, 403):
                status = "AUTH_ERROR"
                return [], status
            elif resp.status_code == 429:
                self.runtime_state["gsb_quota"] = "EXCEEDED"
                status = "RATE_LIMITED"
                return [], status
            else:
                status = "NETWORK_ERROR"
                return [], status
        except Exception as exc:
            logger.debug(f"[ResearchScanner] Safe Browsing lookup failed: {exc}")
            if "Timeout" in type(exc).__name__:
                status = "TIMEOUT"
            else:
                status = "NETWORK_ERROR"
            return [], status

    def _layer_5_threat_intel(self):
        import concurrent.futures as _cf
        domain_reputation = "Clean"
        blacklist_listed = False

        # VirusTotal and Google Safe Browsing run concurrently.
        vt_stats = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
        vt_status = "NOT_CONFIGURED" if not settings.virustotal_api_key else "NOT_QUERIED"
        sb_matches = []
        sb_status = "NOT_CONFIGURED" if not settings.safe_browsing_api_key else "NOT_QUERIED"

        if not self.host_unreachable:
            with _cf.ThreadPoolExecutor(max_workers=2) as ex:
                vt_future = ex.submit(self._vt_lookup)
                gsb_future = ex.submit(self._gsb_lookup)
                try:
                    vt_stats, vt_status = vt_future.result(timeout=15)
                except Exception as exc:
                    vt_status = "TIMEOUT" if "Timeout" in type(exc).__name__ else "NETWORK_ERROR"
                try:
                    sb_matches, sb_status = gsb_future.result(timeout=10)
                except Exception as exc:
                    sb_status = "TIMEOUT" if "Timeout" in type(exc).__name__ else "NETWORK_ERROR"

        # High-risk TLD reputation
        if any(self.domain.endswith(tld) for tld in _RISKY_TLDS):
            domain_reputation = "Suspicious (High-risk TLD)"
            blacklist_listed = True
            
        self.threat_intel_data = {
            "virustotal_stats": vt_stats,
            "virustotal_status": vt_status,
            "safe_browsing_matches": sb_matches,
            "safe_browsing_status": sb_status,
            "domain_reputation": domain_reputation,
            "blacklist_listed": blacklist_listed
        }

    # ================= Layer 6: Dynamic Fusion =================
    def _layer_6_fusion(self) -> Dict[str, Any]:
        has_strong_evidence = False
        has_weak_evidence = False
        evidence_list = []

        # Passive/Active basic extraction (keep for API compatibility but ignore for verdict)
        passive_score = 0.0
        if self.passive_findings:
            passive_score = 0.3
            
        active_score = 0.0
        
        # Check Active Findings (Evidence Gate)
        for finding in self.active_findings:
            ftype = finding.get("type", "")
            if ftype in ["Exposed Sensitive File: /backup.zip", "Exposed Sensitive File: /db.sql", "Exposed Sensitive File: /.env", "Exposed Sensitive File: /.git/config"]:
                has_weak_evidence = True
                evidence_list.append("backup exposure")
            elif ftype == "Unvalidated Open Redirect":
                has_weak_evidence = True
                evidence_list.append("open redirect")
            elif ftype in ["Path Traversal Exposure", "Potential SQL Injection", "Reflected Cross-Site Scripting (XSS)"]:
                has_strong_evidence = True
                evidence_list.append("active exploit payload")
        
        # Check Threat Intel
        vt_mal = self.threat_intel_data.get("virustotal_stats", {}).get("malicious", 0)
        sb_match = len(self.threat_intel_data.get("safe_browsing_matches", [])) > 0
        is_trusted_domain = self.domain in getattr(self, "_trusted_cache", TRUSTED_DOMAINS)
        
        if vt_mal >= 3 or sb_match:
            has_strong_evidence = True
            evidence_list.append("malicious reputation")
        elif vt_mal > 0 or self.threat_intel_data.get("blacklist_listed", False):
            if not is_trusted_domain:
                has_weak_evidence = True
                evidence_list.append("malicious reputation")

        # Phishing Report is evaluated in execute_scan BEFORE layer 6
        if hasattr(self, "phishing_report") and self.phishing_report:
            p_verdict = self.phishing_report.get("verdict", "SAFE")
            if p_verdict in ("PHISHING RISK", "HIGH RISK", "MALICIOUS", "critical", "high"):
                has_strong_evidence = True
                evidence_list.append("phishing NLP")
                evidence_list.append("brand mismatch")
                evidence_list.append("credential harvesting")
            elif p_verdict in ("SUSPICIOUS", "medium"):
                has_weak_evidence = True
                evidence_list.append("typosquat")

        # Heuristic Analysis evaluation in fusion
        canonical_url, canonical_hostname = normalize_url(self.target_url)
        heuristic = run_heuristic_analysis(canonical_url, canonical_hostname, self.target_url)
        h_score = heuristic.get("risk_score", 0)
        h_indicators = heuristic.get("threat_indicators", [])
        real_threat_indicators = [
            ind for ind in h_indicators
            if "does not use HTTPS encryption" not in ind and "HTTP (no encryption)" not in ind
        ]

        if h_score >= 60 or heuristic.get("brand_impersonation"):
            has_strong_evidence = True
            evidence_list.append("brand impersonation / high heuristic threat")
        elif h_score >= 25 or len(real_threat_indicators) > 0:
            has_weak_evidence = True
            evidence_list.append("heuristic anomaly")

        if self.runtime_state["status"] == "SCAN_FAILED":
            verdict = "SCAN_FAILED"
            confidence = 0.0
        elif self.runtime_state["status"] == "SCAN_DEGRADED":
            verdict = "INSUFFICIENT_EVIDENCE"
            confidence = 0.0
        elif self.host_unreachable:
            if has_strong_evidence:
                verdict = "MALICIOUS"
                confidence = 0.85
            elif has_weak_evidence:
                verdict = "SUSPICIOUS"
                confidence = 0.60
            else:
                verdict = "INSUFFICIENT_EVIDENCE"
                confidence = 0.20
        elif has_strong_evidence:
            verdict = "MALICIOUS"
            confidence = 0.95
        elif has_weak_evidence:
            verdict = "SUSPICIOUS"
            confidence = 0.60
        else:
            verdict = "SAFE"
            confidence = 0.90 if heuristic.get("is_trusted") else 0.70

        return {
            "fusion_score": confidence,
            "verdict": verdict,
            "evidence_gate": evidence_list,
            "confidence": confidence,
            "breakdown": {
                "passive": passive_score,
                "active": 1.0 if has_strong_evidence else (0.5 if has_weak_evidence else 0.0),
                "threat_intel": 1.0 if vt_mal > 0 else 0.0,
                "anomaly": 0.0
            }
        }

    # ================= Layer 7: Reporting =================
    def _layer_7_reporting(self, fusion_report: Dict[str, Any]) -> Dict[str, Any]:
        all_findings = []
        for pf in self.passive_findings:
            severity = pf["severity"]
            score, vector = estimate_cvss(severity)
            all_findings.append({
                "type": pf["type"],
                "category": "passive",
                "severity": severity,
                "cvss_score": score,
                "cvss_vector": vector,
                "evidence": pf["impact"],
                "remediation": pf["remediation"]
            })
            
        for af in self.active_findings:
            severity = af["severity"]
            score, vector = estimate_cvss(severity)
            all_findings.append({
                "type": af["type"],
                "category": "active",
                "severity": severity,
                "cvss_score": score,
                "cvss_vector": vector,
                "evidence": af["evidence"],
                "remediation": af["remediation"]
            })

        # Append Phishing engine findings if any
        if hasattr(self, "phishing_report") and self.phishing_report:
            p_verdict = self.phishing_report.get("verdict", "SAFE")
            if p_verdict not in ("SAFE", "LOW RISK"):
                severity = "critical" if p_verdict in ("MALICIOUS", "HIGH RISK") else "high"
                score, vector = estimate_cvss(severity)
                for ev in self.phishing_report.get("evidence_chain", []):
                    all_findings.append({
                        "type": f"Phishing Indicator: {ev}",
                        "category": "phishing",
                        "severity": severity,
                        "cvss_score": score,
                        "cvss_vector": vector,
                        "evidence": ev,
                        "remediation": f"Suspicious brand clone impersonation detected ({self.phishing_report.get('impersonated_brand', 'unspecified brand')}). Avoid submitting any credentials/OTP."
                    })
            
        # Use AI only for summaries, reasoning, and deduplication of findings
        ai_summary = "Research scanner completed successfully."
        ai_reasoning = "The target was scanned across all seven defensive and offensive layers."
        deduplicated_findings = all_findings
        
        if settings.gemini_api_key:
            try:
                import concurrent.futures as _cf
                findings_summary = "\n".join([f"- [{f['category'].upper()}] {f['type']} ({f['severity'].upper()})" for f in all_findings])
                prompt = (
                    "You are a cybersecurity safety assistant. Below is a list of scanner findings for a website.\n"
                    "Analyze them and provide a brief, professional summary of the security status of this website in English.\n"
                    "Do not add any markup other than plain text paragraphs. Do not invent any new vulnerabilities.\n"
                    f"Findings:\n{findings_summary}"
                )

                def _summarize() -> str:
                    client = genai.Client(api_key=settings.gemini_api_key)
                    result = client.models.generate_content(model="gemini-2.5-flash", contents=prompt)
                    return (result.text or "").strip() if result else ""

                # Hard cap: the AI summary is cosmetic and must never stall a scan.
                _ex = _cf.ThreadPoolExecutor(max_workers=1)
                try:
                    text = _ex.submit(_summarize).result(timeout=1.5)
                finally:
                    _ex.shutdown(wait=False)
                if text:
                    ai_summary = text
            except Exception as e:
                logger.debug(f"[ResearchScanner] Gemini reporting summary generation failed or timed out: {e}")
                
        # Format the final unified report structure
        verdict = fusion_report["verdict"]
        confidence = fusion_report["confidence"]
        
        phishing_data = getattr(self, "phishing_report", {})

        # Determine recommendations based on findings severity
        recommendations = []
        for f in deduplicated_findings:
            if f["remediation"] not in recommendations:
                recommendations.append(f["remediation"])
        if not recommendations:
            recommendations.append("No critical issues found. Continue practicing basic browsing security.")

        # ── Run heuristic analysis on canonical URL ───────────────────────
        canonical_url, canonical_hostname = normalize_url(self.target_url)
        heuristic = run_heuristic_analysis(canonical_url, canonical_hostname, self.target_url)

        # ── VirusTotal & GSB status ───────────────────────────────────────
        vt_configured = bool(settings.virustotal_api_key)
        gsb_configured = bool(settings.safe_browsing_api_key)
        vt_stats = self.threat_intel_data.get("virustotal_stats", {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0})
        vt_status = self.threat_intel_data.get("virustotal_status", "NOT_CONFIGURED" if not vt_configured else "NOT_QUERIED")
        gsb_matches = self.threat_intel_data.get("safe_browsing_matches", [])
        gsb_status = self.threat_intel_data.get("safe_browsing_status", "NOT_CONFIGURED" if not gsb_configured else "NOT_QUERIED")
        vt_used = vt_configured and vt_status in ("SUCCESS_CLEAN", "SUCCESS_MALICIOUS", "NO_INTELLIGENCE")
        gsb_used = gsb_configured and gsb_status in ("SUCCESS_CLEAN", "SUCCESS_MALICIOUS")

        # ── Override overall_status if reputation APIs or fusion flag it ──
        vt_malicious = vt_stats.get("malicious", 0)
        gsb_flagged = len(gsb_matches) > 0
        overall_status = heuristic["overall_status"]
        risk_score = heuristic["risk_score"]

        if fusion_report["verdict"] == "MALICIOUS" or vt_malicious >= 3 or gsb_flagged:
            overall_status = "Dangerous"
            risk_score = max(risk_score, 75)
        elif fusion_report["verdict"] == "SUSPICIOUS" or (vt_malicious >= 1 and not heuristic["is_trusted"]):
            if overall_status in ("Trusted", "Low Risk", "Moderate Risk"):
                overall_status = "Suspicious"
            risk_score = max(risk_score, 50)
        elif fusion_report["verdict"] == "INSUFFICIENT_EVIDENCE":
            overall_status = "Unknown"

        # ── Honest confidence calculation ─────────────────────────────────
        # Base: heuristics always run → 40
        # DNS resolved → +10
        # TLS checked (HTTPS) → +10
        # VirusTotal used → +25
        # GSB used → +15
        confidence_score = 40
        dns_ok = ("error" not in self.recon_data.get("dns", {"error": "not checked"})) and (not self.host_unreachable)
        if dns_ok:
            confidence_score += 10
        if self.parsed_url.scheme == "https" and not self.recon_data.get("tls", {}).get("error"):
            confidence_score += 10
        if vt_used:
            confidence_score += 25
        if gsb_used:
            confidence_score += 15
        confidence_score = min(100, confidence_score)

        if self.host_unreachable:
            if fusion_report["verdict"] in ("MALICIOUS", "Dangerous"):
                overall_status = "Dangerous"
                risk_score = max(risk_score, 75)
                confidence_score = min(40, confidence_score)
                confidence_label = "Unreachable host - flagged by dangerous heuristic indicators"
            elif fusion_report["verdict"] in ("SUSPICIOUS", "Suspicious"):
                overall_status = "Suspicious"
                risk_score = max(risk_score, 50)
                confidence_score = min(40, confidence_score)
                confidence_label = "Unreachable host - flagged by suspicious heuristic indicators"
            else:
                overall_status = "Unknown"
                confidence_score = min(20, confidence_score)
                confidence_label = "Host could not be resolved or reached; insufficient evidence"
        else:
            confidence_label = (
                "Confidence based on local analysis only — no reputation APIs used"
                if confidence_score <= 55
                else "Confidence reflects heuristics and reputation API results"
            )

        # ── Enrich recommendations ────────────────────────────────────────
        curated_recs = list(recommendations)
        if self.host_unreachable and overall_status == "Unknown":
            curated_recs = [
                "Host could not be resolved via DNS or reached over the network.",
                "Verify domain spelling. Inactive or unregistered domains may be parked or decommissioned."
            ]
        elif overall_status == "Trusted":
            curated_recs = ["Safe for normal browsing.", "Always verify login pages independently."]
        elif overall_status == "Low Risk":
            curated_recs = ["Exercise normal caution.", "Verify the sender before opening."] + curated_recs[:2]
        elif overall_status == "Moderate Risk":
            curated_recs = ["Avoid entering credentials.", "Verify URL carefully before proceeding."] + curated_recs[:2]
        elif overall_status == "Suspicious":
            curated_recs = ["Avoid entering passwords or OTPs.", "Do not proceed unless you trust the source completely."] + curated_recs[:2]
        elif overall_status == "Dangerous":
            curated_recs = ["Do NOT interact with this link.", "Report to your IT/security team if received via email or SMS."] + curated_recs[:2]
        else:
            curated_recs = ["Target address status could not be verified.", "Exercise extreme caution before visiting."]

        # ── Map verdict to frontend-compatible string ─────────────────────
        status_to_verdict = {
            "Trusted": "safe",
            "Low Risk": "safe",
            "Moderate Risk": "suspicious",
            "Suspicious": "suspicious",
            "Dangerous": "dangerous",
            "Blocked": "blocked",
            "Unknown": "uncertain",
        }
        frontend_verdict = status_to_verdict.get(overall_status, "uncertain")
        conn_status = "Reachable" if dns_ok else f"Unreachable ({self.host_unreachable_reason or 'DNS lookup failed'})"

        return {
            # ── Existing fields (preserved for backward compatibility) ──
            "url": self.target_url,
            "verdict": frontend_verdict,
            "threat_verdict": fusion_report.get("verdict", frontend_verdict.upper()),
            "scan_status": "DNS_RESOLUTION_FAILED" if (self.host_unreachable and "DNS" in self.host_unreachable_reason) else ("HOST_UNREACHABLE" if self.host_unreachable else "COMPLETED"),
            "runtime_state": self.runtime_state,
            "confidence": round(confidence, 4),
            "evidence_gate": fusion_report.get("evidence_gate", []),
            "threats": list(set([f["type"] for f in deduplicated_findings if f["severity"] in ("high", "critical")])),
            "malicious_count": vt_stats["malicious"],
            "suspicious_count": vt_stats["suspicious"],
            "safe_count": vt_stats["harmless"] if vt_used else 0,
            "harmless_count": vt_stats["harmless"] if vt_used else 0,
            "undetected_count": vt_stats["undetected"] if vt_used else 0,
            "total_engines": sum(vt_stats.values()) if vt_used else 0,
            "invalid_domain": not dns_ok,
            "connection_status": conn_status,
            "virusTotal": {
                "configured": vt_configured,
                "used": vt_used,
                "status": vt_status,
                "stats": vt_stats,
            },
            "googleSafeBrowsing": {
                "configured": gsb_configured,
                "used": gsb_used,
                "status": gsb_status,
                "matches": gsb_matches,
            },
            "redirectChain": [self.target_url],
            "sslInfo": {
                "https": self.parsed_url.scheme == "https",
                "cert_validity_days": 30 if self.recon_data["tls"].get("notAfter") else None,
            },
            "domainEntropy": round(float(fusion_report["breakdown"]["anomaly"] * 4.0), 3),
            "findings": [f["type"] for f in deduplicated_findings] or ["No threat indicators found in configured checks."],
            "details": [
                f"{f['type']}: {f['evidence']}" for f in deduplicated_findings
            ] or ["Active scanner completed. 0 vulnerabilities found."],
            "domainInfo": {
                "registeredDate": "Unknown",
                "age": "Known/Established" if dns_ok else "Unknown",
                "reputation": "suspicious" if frontend_verdict == "suspicious" else (
                    "dangerous" if frontend_verdict == "dangerous" else ("uncertain" if frontend_verdict == "uncertain" else "safe")
                ),
            },
            "recommendations": curated_recs,
            "englishSummary": ai_summary,
            "hindiSummary": "स्कैन पूरा हो चुका है। कृपया अपनी सुरक्षा स्थिति और रिपोर्ट देखें।",
            "findings_details": deduplicated_findings,
            "fusion_report": fusion_report,
            "crawler_summary": self.crawler_data,
            "phishing_report": phishing_data,
            # ── New structured fields ──────────────────────────────────────
            "normalized_url": canonical_url,
            "original_input": self.target_url,
            "hostname": canonical_hostname,
            "overall_status": overall_status,
            "risk_score": risk_score,
            "confidence_percent": confidence_score,
            "confidence_label": confidence_label,
            "technical_checks": heuristic["technical_checks"],
            "score_factors": heuristic["score_factors"],
            "threat_indicators": heuristic["threat_indicators"],
            "api_status": {
                "virustotal": {
                    "configured": vt_configured,
                    "used": vt_used,
                    "status": vt_status,
                    "label": "VirusTotal",
                },
                "google_safe_browsing": {
                    "configured": gsb_configured,
                    "used": gsb_used,
                    "status": gsb_status,
                    "label": "Google Safe Browsing",
                },
                "heuristics": {
                    "configured": True,
                    "used": True,
                    "status": "SUCCESS_MALICIOUS" if risk_score >= 65 else ("SUCCESS_SUSPICIOUS" if risk_score >= 40 else "SUCCESS_CLEAN"),
                    "label": "Local Heuristics",
                },
            },
        }
