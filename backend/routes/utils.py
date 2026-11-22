import hashlib
import logging
import re
import time
import socket
import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

import requests
import numpy as np


PANIC_KEYWORDS = {
    "scared", "panic", "afraid", "help me", "lost money", "kya karu",
    "ghabra", "dar lag raha", "confused", "please help", "urgent",
    "paise gaye", "hack ho gaya", "account hack", "what to do",
    "emergency", "bahut dar", "kuch samajh nahi", "trapped",
    "fraud ho gaya", "dhoka", "loot liya", "cheat hua",
}

CRISIS_KEYWORDS = {
    "suicide", "kill myself", "die", "hopeless", "end my life",
    "marna hai", "jeena nahi", "self harm", "no point living",
    "zindagi se", "khatam karna", "can't take it anymore",
}

# Time-sensitive urgency triggers (used for UPI/payment fraud triage)
URGENCY_KEYWORDS = {
    "just now", "abhi abhi", "right now", "few minutes ago",
    "1 hour", "2 hours", "just happened", "abhi hua",
    "paise abhi gaye", "just sent money", "now only",
}

CRISIS_RESPONSE_EN = (
    "You are not alone. Please get immediate support: "
    "iCall: 9152987821 | Vandrevala Foundation: 1860-2662-345. "
    "If you are in immediate danger, call your local emergency services now."
)

CRISIS_RESPONSE_HI = (
    "आप अकेले/अकेली नहीं हैं। तुरंत सहायता लें: "
    "iCall: 9152987821 | वंद्रेवाला फाउंडेशन: 1860-2662-345। "
    "यदि तुरंत खतरा है, तो स्थानीय आपातकालीन सेवाओं पर अभी कॉल करें।"
)

# Backward compatibility (older callers may import CRISIS_RESPONSE)
CRISIS_RESPONSE = CRISIS_RESPONSE_EN


def detect_emotion(text: str) -> str:
    lowered = text.lower()
    if any(k in lowered for k in CRISIS_KEYWORDS):
        return "crisis"
    if any(k in lowered for k in PANIC_KEYWORDS):
        return "panic"
    if any(k in lowered for k in URGENCY_KEYWORDS):
        return "panic"  # urgency escalates to panic for faster triage
    if re.search(r"\b(thank you|ok|fine|samajh gaya|samajh gayi|theek hai|dhanyavad)\b", lowered):
        return "calm"
    return "normal"


def sha_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def now_ts() -> int:
    return int(time.time())


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def domain_from_url(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def url_scam_signals(url: str) -> List[str]:
    signals: List[str] = []
    lowered = url.lower()
    host = domain_from_url(lowered)
    if "@" in lowered:
        signals.append("URL contains '@' redirection pattern")
    if re.search(r"(paytm|sbi|hdfc|icici|axis)[-_.]?(secure|verify|update)", lowered):
        signals.append("Possible fake banking verification pattern")
    if re.search(r"(bit\.ly|tinyurl\.com|rb\.gy|cutt\.ly)", lowered):
        signals.append("Shortened URL used to hide destination")
    if re.search(r"https?:\/\/[^\/]*\d{2,}", lowered):
        signals.append("Suspicious numeric-heavy domain")
    if host.startswith("xn--"):
        signals.append("Punycode domain detected (possible homograph attack)")
    if any(host.endswith(tld) for tld in [".zip", ".mov", ".top", ".click", ".xyz"]):
        signals.append("High-risk top-level domain often seen in scams")
    if re.search(r"(login|verify|urgent|update|reward|wallet|kyc|gift|refund)", lowered):
        signals.append("Urgency/social-engineering keywords present in URL")
    return signals


def safe_request_json(
    method: str,
    url: str,
    *,
    timeout: int = 10,
    headers: Dict[str, str] | None = None,
    json_body: Dict[str, Any] | None = None,
) -> Dict[str, Any] | None:
    try:
        resp = requests.request(
            method=method,
            url=url,
            timeout=timeout,
            headers=headers,
            json=json_body,
        )
        if resp.ok:
            return resp.json()
    except Exception as exc:
        logging.debug("Request failed for %s: %s", url, exc)
    return None

import tempfile
import os

def parse_alternate_ip(host: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """
    Parses IP addresses in standard or alternate encodings (decimal integer,
    hexadecimal, dotted octal, dotted hex, IPv6-mapped IPv4).
    Returns an ipaddress object if valid, else None.
    """
    clean = host.strip("[]").strip()
    try:
        return ipaddress.ip_address(clean)
    except ValueError:
        pass

    # Decimal integer IP (e.g., 2130706433 = 127.0.0.1, 2852039166 = 169.254.169.254)
    if clean.isdigit():
        try:
            val = int(clean)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass

    # Hexadecimal integer IP (e.g., 0x7f000001 = 127.0.0.1)
    if clean.lower().startswith("0x"):
        try:
            val = int(clean, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass

    # Dotted octal or dotted hex representation (e.g. 0177.0.0.1 or 0x7f.0.0.1)
    parts = clean.split(".")
    if len(parts) == 4:
        try:
            octets = []
            for p in parts:
                if p.lower().startswith("0x"):
                    octets.append(int(p, 16))
                elif p.startswith("0") and len(p) > 1 and p.isdigit():
                    octets.append(int(p, 8))
                elif p.isdigit():
                    octets.append(int(p, 10))
                else:
                    return None
            if all(0 <= o <= 255 for o in octets):
                return ipaddress.IPv4Address((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3])
        except Exception:
            pass

    return None


def is_restricted_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address | str) -> Tuple[bool, Optional[str]]:
    """
    Evaluates whether an IP address targets a restricted/internal destination.
    Properly handles IPv4, IPv6, IPv4-mapped IPv6 (::ffff:0:0/96), and
    NAT64 translation prefixes (64:ff9b::/96 RFC 6052, 64:ff9b:1::/48 RFC 8215).
    """
    if isinstance(ip, str):
        try:
            ip = ipaddress.ip_address(ip)
        except ValueError:
            return True, f"Invalid IP address format ({ip})"

    if isinstance(ip, ipaddress.IPv4Address):
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return True, f"Restricted/internal IPv4 address ({ip})"
        return False, None

    # IPv6 checks
    # 1. IPv4-mapped IPv6 (::ffff:127.0.0.1)
    if ip.ipv4_mapped:
        return is_restricted_ip(ip.ipv4_mapped)

    # 2. NAT64 translation prefixes (RFC 6052 WKP 64:ff9b::/96 and RFC 8215 Local 64:ff9b:1::/48)
    nat64_wkp = ipaddress.IPv6Network("64:ff9b::/96")
    nat64_local = ipaddress.IPv6Network("64:ff9b:1::/48")
    if ip in nat64_wkp or ip in nat64_local:
        # Extract embedded 32-bit IPv4 address from lower bits
        embedded_ipv4 = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        is_restricted, reason = is_restricted_ip(embedded_ipv4)
        if is_restricted:
            return True, f"NAT64 address embeds restricted IPv4 address ({embedded_ipv4}): {reason}"
        # If the embedded IPv4 address is a public, routable IP, it is safe public NAT64 traffic
        return False, None

    # 3. Standard IPv6 restricted ranges
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True, f"Restricted/internal IPv6 address ({ip})"

    return False, None


def is_safe_public_url(url: str) -> Tuple[bool, str | None]:
    """
    Validates whether a URL targets a safe, public internet endpoint.
    Blocks SSRF targets: localhost, 127.0.0.1, alternate IP representations (int/hex/octal),
    private RFC-1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), link-local /
    cloud metadata (169.254.169.254, fd00:ec2::254), loopback IPv6 (::1), multicast,
    restricted internal ports, and non-http(s) schemes.
    Properly permits public IPv4 endpoints reached via NAT64 translation (RFC 6052).
    Returns (is_safe, error_message).
    """
    if not url or not isinstance(url, str):
        return False, "Invalid URL input."

    try:
        parsed = urlparse(url.strip())
    except Exception:
        return False, "Invalid URL format."

    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return False, f"Unsupported URL scheme '{scheme}'. Only http and https are permitted."

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return False, "URL does not contain a valid hostname."

    # Immediate string check for loopback, local domains, or common SSRF aliases
    if hostname in {"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"}:
        return False, "Access to localhost or loopback addresses is forbidden."

    # Reject cloud metadata hostnames directly
    metadata_hosts = {
        "metadata.google.internal", "instance-data", "metadata",
        "metadata.nic.in", "169.254.169.254", "fd00:ec2::254"
    }
    if hostname in metadata_hosts:
        return False, "Access to internal cloud metadata service is forbidden."

    # Port restriction: block known internal database / administrative service ports
    restricted_ports = {22, 25, 111, 2375, 2376, 2379, 3306, 5432, 6379, 8500, 9200, 11211, 27017}
    if parsed.port and parsed.port in restricted_ports:
        return False, f"Access to restricted internal service port ({parsed.port}) is blocked."

    # Check for direct or alternate IP representation before DNS
    direct_ip = parse_alternate_ip(hostname)
    if direct_ip:
        restricted, reason = is_restricted_ip(direct_ip)
        if restricted:
            return False, f"Target host represents a restricted/internal IP address ({direct_ip}): {reason}. Request blocked for SSRF protection."

    # Resolve IP addresses (handles both IPv4 and IPv6)
    try:
        addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        # DNS failed to resolve — not an internal IP, safe to let downstream handle or report
        return True, None
    except Exception as exc:
        return False, f"Host address resolution error: {exc}"

    for item in addr_info:
        ip_str = item[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
            restricted, reason = is_restricted_ip(ip)
            if restricted:
                return False, f"Target host resolves to restricted/internal IP address ({ip_str}): {reason}. Request blocked for SSRF protection."
        except ValueError:
            return False, f"Invalid resolved IP format ({ip_str})."

    return True, None


def download_media_from_url(url: str, max_size_mb: int = 55, timeout: int = 15) -> tuple[str | None, str | None]:
    """
    Safely downloads media from a URL to a temporary file.
    Follows redirects hop-by-hop, verifying SSRF protection at every redirect.
    Returns (temp_file_path, error_message).
    """
    current_url = url
    max_hops = 5
    resp = None

    try:
        for _ in range(max_hops):
            is_safe, ssrf_err = is_safe_public_url(current_url)
            if not is_safe:
                return None, ssrf_err or "Access to the requested URL is forbidden (SSRF protection)."

            resp = requests.get(
                current_url,
                stream=True,
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": "veyron-backend"}
            )
            if resp.is_redirect and "Location" in resp.headers:
                next_url = urljoin(current_url, resp.headers["Location"])
                current_url = next_url
            else:
                break

        if resp is None:
            return None, "Failed to initiate media download request."

        resp.raise_for_status()
        
        content_type = resp.headers.get("Content-Type", "").lower()
        if not content_type.startswith(("image/", "video/")):
            return None, f"Unsupported media type from URL: {content_type}"
            
        content_length = resp.headers.get("Content-Length")
        if content_length and int(content_length) > max_size_mb * 1024 * 1024:
            return None, f"File exceeds maximum allowed size ({max_size_mb}MB)"
            
        ext = ".tmp"
        if "image/jpeg" in content_type: ext = ".jpg"
        elif "image/png" in content_type: ext = ".png"
        elif "image/webp" in content_type: ext = ".webp"
        elif "video/mp4" in content_type: ext = ".mp4"
        elif "video/quicktime" in content_type: ext = ".mov"
        elif "video/x-msvideo" in content_type: ext = ".avi"
        elif "video/webm" in content_type: ext = ".webm"
        
        temp_fd, temp_path = tempfile.mkstemp(suffix=ext)
        downloaded_size = 0
        
        with os.fdopen(temp_fd, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    downloaded_size += len(chunk)
                    if downloaded_size > max_size_mb * 1024 * 1024:
                        os.remove(temp_path)
                        return None, f"File exceeds maximum allowed size ({max_size_mb}MB)"
                    f.write(chunk)
                    
        return temp_path, None
    except requests.exceptions.Timeout:
        return None, "Download timed out."
    except Exception as exc:
        logging.error(f"Failed to download media from URL {url}: {exc}")
        return None, "Failed to download media from the provided URL."


def sanitize_for_json(obj: Any, key_path: str = "root") -> Any:
    """
    Recursively converts numpy types and other non-standard types 
    to JSON-serializable native Python types.
    Use module-name checking for maximum robustness across numpy versions.
    """
    if obj is None:
        return None

    # Get type info once
    obj_type = type(obj)
    type_str = str(obj_type)
    module_name = getattr(obj_type, "__module__", "")

    # 1. Handle Numpy types via module name or string check
    if "numpy" in module_name or "numpy" in type_str:
        # Robust scalar conversion
        
        # Handle scalars
        if "bool" in type_str:
            return bool(obj)
        if "integer" in type_str or "int" in type_str:
            return int(obj)
        if "floating" in type_str or "float" in type_str:
            return float(obj)
        if "ndarray" in type_str:
            return [sanitize_for_json(x, f"{key_path}[{i}]") for i, x in enumerate(obj.tolist())]
        
        # Fallback for other numpy-related types (e.g. np.void, np.datetime64)
        try:
            return obj.item() if hasattr(obj, "item") else str(obj)
        except:
            return str(obj)

    # 2. Handle Collections
    if isinstance(obj, dict):
        return {str(k): sanitize_for_json(v, f"{key_path}.{k}") for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, np.ndarray)): # np.ndarray check here too just in case
        if hasattr(obj, "tolist"):
            return [sanitize_for_json(x, f"{key_path}[{i}]") for i, x in enumerate(obj.tolist())]
        return [sanitize_for_json(x, f"{key_path}[{i}]") for i, x in enumerate(obj)]
    
    # 3. Native types
    if isinstance(obj, (str, int, float, bool)):
        return obj
        
    # 4. Fallback for other unknown types (e.g. dataclasses, Pydantic models)
    if hasattr(obj, "__dict__"):
        return sanitize_for_json(vars(obj), key_path)
        
    logging.warning(f"[Serialization Safety] Field: {key_path} | Unknown non-serializable type: {obj_type}")
    try:
        return str(obj)
    except:
        return None
