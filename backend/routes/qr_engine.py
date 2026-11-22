import logging
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import cv2
import numpy as np

from routes.utils import is_safe_public_url, url_scam_signals
from routes.website_scanner import normalize_url, ResearchScanner

logger = logging.getLogger("veyron-backend.qr_engine")

# ─────────────────────────────────────────────────────────────
# QR Code Image Decoding
# ─────────────────────────────────────────────────────────────

def decode_qr_image_bytes(image_bytes: bytes) -> Tuple[Optional[str], Optional[str]]:
    """
    Decodes a QR code from raw image bytes using OpenCV.
    Applies multi-engine detection (QRCodeDetectorAruco + standard QRCodeDetector),
    ISO/IEC quiet-zone padding, adaptive scaling, contrast normalization,
    Otsu thresholding, and inverted pass.
    Returns (decoded_text, error_message).
    """
    if not image_bytes:
        return None, "Empty image data received."

    try:
        np_arr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        if img is None:
            return None, "Could not decode image file. Unsupported or corrupted format."

        detectors = []
        if hasattr(cv2, "QRCodeDetectorAruco"):
            detectors.append(cv2.QRCodeDetectorAruco())
        detectors.append(cv2.QRCodeDetector())

        h, w = img.shape[:2]

        # Ensure minimum module resolution for small / tight crops
        base_img = img
        if max(h, w) < 300:
            scale_factor = int(np.ceil(400.0 / max(h, w)))
            base_img = cv2.resize(img, (w * scale_factor, h * scale_factor), interpolation=cv2.INTER_NEAREST)

        # Standard ISO/IEC 18004 quiet zone: add 15-20% white border padding
        bh, bw = base_img.shape[:2]
        pad = max(28, int(min(bh, bw) * 0.15))
        padded_bgr = cv2.copyMakeBorder(base_img, pad, pad, pad, pad, cv2.BORDER_CONSTANT, value=[255, 255, 255])

        # Prepare candidate representations
        gray_orig = cv2.cvtColor(base_img, cv2.COLOR_BGR2GRAY)
        gray_padded = cv2.cvtColor(padded_bgr, cv2.COLOR_BGR2GRAY)

        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        contrast_padded = clahe.apply(gray_padded)
        _, thresh_padded = cv2.threshold(contrast_padded, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        thresh_inv = cv2.bitwise_not(thresh_padded)

        candidates = [
            img,
            padded_bgr,
            gray_padded,
            gray_orig,
            contrast_padded,
            thresh_padded,
            thresh_inv,
        ]

        # If image was large, also add downscaled padded variant
        if max(bh, bw) > 1600:
            scale = 1200.0 / max(bh, bw)
            candidates.append(cv2.resize(gray_padded, (int((bw + 2 * pad) * scale), int((bh + 2 * pad) * scale)), interpolation=cv2.INTER_AREA))

        found_matrix = False
        for det in detectors:
            for cand in candidates:
                try:
                    text, bbox, _ = det.detectAndDecode(cand)
                    if text and text.strip():
                        return text.strip(), None
                    if bbox is not None and len(bbox) > 0:
                        found_matrix = True
                except Exception:
                    continue

        if found_matrix:
            return None, "QR code pattern was detected, but content could not be decoded. The image may be blurry, low resolution, or damaged."
        return None, "No QR code could be detected in the provided image. Please ensure the code is clearly framed, well-lit, and in focus."
    except Exception as exc:
        logger.error(f"[QREngine] Decoding failed: {exc}")
        return None, f"QR decoding error: {exc}"


# ─────────────────────────────────────────────────────────────
# Payload Classification & Security Assessment
# ─────────────────────────────────────────────────────────────

def classify_payload_type(raw_text: str) -> str:
    """Classifies raw QR payload string into url, upi, wifi, contact, or text."""
    s = raw_text.strip()
    lowered = s.lower()

    if lowered.startswith("upi://") or lowered.startswith("upi:"):
        return "upi"
    if lowered.startswith("wifi:") or lowered.startswith("wif:"):
        return "wifi"
    if lowered.startswith("begin:vcard") or lowered.startswith("mecard:"):
        return "contact"
    if any(lowered.startswith(f"{sch}:") for sch in ["http", "https", "javascript", "data", "file", "intent", "blob", "about", "vbscript"]):
        return "url"
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$", s):
        return "url"

    return "text"


def analyze_upi_payload(raw_text: str) -> Dict[str, Any]:
    """
    Parses and evaluates UPI payment strings (upi://pay?...).
    Performs threat analysis for payee spoofing, unverified merchants,
    and 'pay-to-receive' fraud patterns.
    """
    parsed = urllib.parse.urlparse(raw_text)
    params = urllib.parse.parse_qs(parsed.query)

    pa = params.get("pa", [""])[0].strip()   # Payee VPA
    pn = params.get("pn", [""])[0].strip()   # Payee Name
    am = params.get("am", [""])[0].strip()   # Amount
    cu = params.get("cu", ["INR"])[0].strip()# Currency
    mc = params.get("mc", [""])[0].strip()   # Merchant Code
    tr = params.get("tr", [""])[0].strip()   # Transaction Ref
    tn = params.get("tn", [""])[0].strip()   # Transaction Note

    threat_indicators: List[str] = []
    recommendations: List[str] = []
    risk_score = 20

    # 1. Fundamental UPI Safety Advisory (Universal in India)
    recommendations.append("CRITICAL: Scanning a QR code only SENDS money. You never need to scan a QR code to RECEIVE money, lottery winnings, or refunds.")
    recommendations.append("Note: Heuristic analysis identifies common scam patterns, but cannot verify the legitimate identity of the recipient. Always verify the recipient on your banking app.")

    # 2. Amount analysis
    has_amount = False
    amount_val = 0.0
    if am:
        try:
            amount_val = float(am)
            has_amount = True
            if amount_val > 50000:
                risk_score += 35
                threat_indicators.append(f"High pre-set transfer amount: ₹{amount_val:,.2f}")
            elif amount_val > 10000:
                risk_score += 20
                threat_indicators.append(f"Substantial pre-set transfer amount: ₹{amount_val:,.2f}")
        except ValueError:
            pass

    if not has_amount:
        threat_indicators.append("Dynamic amount QR: Amount is not pre-set. The app will prompt you to enter the payment amount manually.")

    # 3. Payee VPA Spoofing & Fraud Keyword Detection
    pa_lower = pa.lower()
    pn_lower = pn.lower()
    tn_lower = tn.lower()

    suspicious_vpa_words = [
        "refund", "support", "cashback", "lottery", "kyc", "verification",
        "customercare", "helpdesk", "reward", "olx", "quikr", "prize",
        "police", "cbi", "rbi", "income-tax", "challan", "toll",
    ]

    for word in suspicious_vpa_words:
        if word in pa_lower or word in pn_lower or word in tn_lower:
            risk_score += 30
            threat_indicators.append(f"Deceptive keyword detected ('{word}') in payee details, frequently used in payment social-engineering scams.")

    # 4. Legitimate Brand Impersonation in UPI handle
    banks = ["sbi", "hdfc", "icici", "axis", "pnb", "bob", "paytm", "phonepe", "gpay"]
    if any(b in pa_lower.split("@")[0] for b in banks) and not any(pa_lower.endswith(f"@{b}") for b in banks):
        risk_score += 25
        threat_indicators.append("Payee VPA appears to mimic a financial institution name in username prefix.")

    risk_score = min(100, max(0, risk_score))
    verdict = "HIGH RISK" if risk_score >= 70 else ("SUSPICIOUS" if risk_score >= 40 else "NO KNOWN THREAT DETECTED")

    if verdict != "NO KNOWN THREAT DETECTED":
        recommendations.append("Verify the payee name on your banking app screen before entering any UPI PIN.")
        recommendations.append("Never enter your UPI PIN on screens prompted by strangers. UPI PIN is solely used for deducting money.")
    else:
        recommendations.append(f"Verify that you intend to transfer funds to '{pn or pa}' before authorizing with your PIN.")

    return {
        "payload_type": "upi",
        "verdict": verdict,
        "risk_level": verdict,
        "legacy_verdict": "dangerous" if verdict == "HIGH RISK" else ("suspicious" if verdict == "SUSPICIOUS" else "safe"),
        "risk_score": risk_score,
        "parsed_data": {
            "payee_vpa": pa,
            "payee_name": pn,
            "amount": amount_val if has_amount else None,
            "currency": cu,
            "merchant_code": mc or None,
            "transaction_ref": tr or None,
            "transaction_note": tn or None,
        },
        "threat_indicators": threat_indicators,
        "recommendations": recommendations,
        "englishSummary": f"UPI Payment Request to '{pn or pa}'" + (f" for ₹{amount_val:,.2f}" if has_amount else " (Custom amount)"),
        "hindiSummary": f"'{pn or pa}' को UPI भुगतान अनुरोध" + (f" राशि: ₹{amount_val:,.2f}" if has_amount else " (कस्टम राशि)"),
    }


def analyze_wifi_payload(raw_text: str) -> Dict[str, Any]:
    """
    Parses and evaluates Wi-Fi QR payloads (WIFI:T:WPA;S:MyNet;P:password;;).
    Flags unencrypted networks (nopass), deprecated WEP encryption, and hidden SSIDs.
    """
    content = raw_text.strip()
    if content.upper().startswith("WIFI:"):
        content = content[5:]

    fields: Dict[str, str] = {}
    tokens = re.split(r"(?<!\\);", content)
    for token in tokens:
        if ":" in token:
            k, v = token.split(":", 1)
            fields[k.upper()] = v.replace("\\;", ";").replace("\\:", ":")

    auth_type = fields.get("T", "nopass").upper()
    ssid = fields.get("S", "Unknown Network")
    password = fields.get("P", "")
    hidden = fields.get("H", "").lower() in {"true", "1", "yes"}

    threat_indicators: List[str] = []
    recommendations: List[str] = []
    risk_score = 15

    if auth_type in {"NOPASS", "NONE", ""} or not password:
        risk_score = 65
        verdict = "SUSPICIOUS"
        threat_indicators.append("Security Configuration Risk: Open / unencrypted network. Transmitted data is unencrypted over the air.")
        threat_indicators.append("Vulnerability to local packet sniffing, Man-in-the-Middle (MitM) inspection, and rogue access point spoofing.")
        recommendations.append("Open Wi-Fi is an unencrypted network configuration risk, not proof of malicious behavior. Exercise caution before connecting.")
        recommendations.append("If connecting, use a verified VPN and do not transmit sensitive passwords or financial credentials.")
    elif auth_type == "WEP":
        risk_score = 60
        verdict = "SUSPICIOUS"
        threat_indicators.append("Deprecated WEP encryption detected. WEP has known cryptographic vulnerabilities and can be cracked quickly.")
        recommendations.append("Upgrade router security configuration to WPA2-AES or WPA3.")
    else:
        verdict = "NO KNOWN THREAT DETECTED"
        threat_indicators.append(f"Network uses {auth_type} wireless encryption.")
        recommendations.append(f"Network uses {auth_type} encryption. Note: WPA2/WPA3 secures the radio transmission, but does not verify the identity or trustworthiness of the network operator.")

    if hidden:
        threat_indicators.append("Hidden network (SSID broadcast disabled).")

    return {
        "payload_type": "wifi",
        "verdict": verdict,
        "risk_level": verdict,
        "legacy_verdict": "dangerous" if verdict == "HIGH RISK" else ("suspicious" if verdict == "SUSPICIOUS" else "safe"),
        "risk_score": risk_score,
        "parsed_data": {
            "ssid": ssid,
            "security_type": auth_type,
            "password_present": bool(password),
            "is_hidden": hidden,
        },
        "threat_indicators": threat_indicators,
        "recommendations": recommendations,
        "englishSummary": f"Wi-Fi Connection Profile for '{ssid}' ({auth_type} Security)",
        "hindiSummary": f"'{ssid}' के लिए वाई-फाई कनेक्शन प्रोफ़ाइल ({auth_type} सुरक्षा)",
    }


def analyze_contact_payload(raw_text: str) -> Dict[str, Any]:
    """Parses and evaluates vCard / meCard contact payloads."""
    name = "Unknown Contact"
    phones = []
    emails = []
    urls = []
    org = ""

    for line in raw_text.splitlines():
        line = line.strip()
        if line.startswith("FN:"):
            name = line[3:].strip()
        elif line.startswith("N:") and name == "Unknown Contact":
            name = line[2:].replace(";", " ").strip()
        elif line.startswith("TEL"):
            phones.append(line.split(":")[-1].strip())
        elif line.startswith("EMAIL"):
            emails.append(line.split(":")[-1].strip())
        elif line.startswith("URL"):
            urls.append(line.split(":")[-1].strip())
        elif line.startswith("ORG:"):
            org = line[4:].strip()

    threat_indicators: List[str] = []
    recommendations: List[str] = []
    risk_score = 10

    # Inspect URLs inside contact card
    for u in urls:
        is_safe, err = is_safe_public_url(u)
        if not is_safe:
            risk_score += 40
            threat_indicators.append(f"Contact card references private/suspicious URL: {u}")

    # Impersonation checks
    impersonation_keywords = ["police", "cbi", "cyber cell", "rbi", "bank support", "customer care"]
    combined_contact_text = f"{name} {org}".lower()
    if any(k in combined_contact_text for k in impersonation_keywords):
        risk_score += 35
        threat_indicators.append("Contact details claim official government or banking authority. Verify authenticity through official directory before calling.")

    risk_score = min(100, max(0, risk_score))
    verdict = "SUSPICIOUS" if risk_score >= 40 else "NO KNOWN THREAT DETECTED"
    recommendations.append("Review contact details before saving to your device address book.")

    return {
        "payload_type": "contact",
        "verdict": verdict,
        "risk_level": verdict,
        "legacy_verdict": "suspicious" if verdict == "SUSPICIOUS" else "safe",
        "risk_score": risk_score,
        "parsed_data": {
            "name": name,
            "organization": org or None,
            "phone_numbers": phones,
            "emails": emails,
            "urls": urls,
        },
        "threat_indicators": threat_indicators,
        "recommendations": recommendations,
        "englishSummary": f"Contact Card for '{name}'" + (f" ({org})" if org else ""),
        "hindiSummary": f"'{name}' का संपर्क कार्ड" + (f" ({org})" if org else ""),
    }


def analyze_text_payload(raw_text: str) -> Dict[str, Any]:
    """Parses and evaluates arbitrary text payloads for social engineering patterns."""
    text_sample = raw_text.strip()
    lowered = text_sample.lower()

    threat_indicators: List[str] = []
    recommendations: List[str] = []
    risk_score = 10

    scam_keywords = {
        "otp": "Mentions OTP or one-time code requests.",
        "pin": "Requests secret PIN or password credentials.",
        "urgent": "Employs high-pressure urgency tactics.",
        "lottery": "Claims unexpected lottery or lucky draw winnings.",
        "winner": "Claims prize winner status.",
        "block": "Threatens account or service blockage.",
        "blocked": "Claims account suspension or SIM block threats.",
        "electricity": "Threatens power disconnection unless urgent payment is made.",
        "disconnected": "Threatens service disconnection.",
        "kyc": "Demands immediate KYC update to avoid account freeze.",
    }

    for kw, msg in scam_keywords.items():
        if re.search(r"\b" + re.escape(kw) + r"\b", lowered):
            risk_score += 15
            threat_indicators.append(msg)

    risk_score = min(100, max(0, risk_score))
    verdict = "HIGH RISK" if risk_score >= 70 else ("SUSPICIOUS" if risk_score >= 40 else "NO KNOWN THREAT DETECTED")

    if verdict != "NO KNOWN THREAT DETECTED":
        recommendations.append("This QR code text uses keywords typical of phishing and social-engineering scams.")
        recommendations.append("Do not send personal information, OTPs, or money based on this message.")
    else:
        recommendations.append("Standard text QR payload. No overt social-engineering indicators detected.")

    return {
        "payload_type": "text",
        "verdict": verdict,
        "risk_level": verdict,
        "legacy_verdict": "dangerous" if verdict == "HIGH RISK" else ("suspicious" if verdict == "SUSPICIOUS" else "safe"),
        "risk_score": risk_score,
        "parsed_data": {
            "text": text_sample[:500],
            "char_count": len(text_sample),
        },
        "threat_indicators": threat_indicators,
        "recommendations": recommendations,
        "englishSummary": f"Plain text payload ({len(text_sample)} characters)",
        "hindiSummary": f"सामान्य टेक्स्ट पेलोड ({len(text_sample)} अक्षर)",
    }


def evaluate_qr_payload(raw_text: str) -> Dict[str, Any]:
    """
    Main evaluation dispatcher.
    Classifies payload, executes deep analysis, and enforces zero-trust
    reporting with NO AUTOMATIC NAVIGATION.
    """
    if not raw_text or not isinstance(raw_text, str):
        return {
            "payload_type": "text",
            "raw_payload": "",
            "verdict": "SCAN FAILED",
            "risk_level": "SCAN FAILED",
            "risk_score": 0,
            "threat_indicators": ["Empty or invalid payload received."],
            "recommendations": ["Ensure QR code contains readable data."],
            "englishSummary": "Empty payload",
            "hindiSummary": "खाली पेलोड",
        }

    # Bounded payload length defense
    if len(raw_text) > 8192:
        return {
            "payload_type": "text",
            "raw_payload": raw_text[:300] + "... [TRUNCATED]",
            "verdict": "SUSPICIOUS",
            "risk_level": "SUSPICIOUS",
            "risk_score": 60,
            "threat_indicators": [f"Payload length ({len(raw_text)} chars) exceeds standard QR capacity (8KB). Truncated for security."],
            "recommendations": ["Oversized QR payloads may attempt buffer overflow or resource exhaustion."],
            "englishSummary": "Oversized QR payload",
            "hindiSummary": "अत्यधिक बड़ा क्यूआर पेलोड",
        }

    payload_type = classify_payload_type(raw_text)

    if payload_type == "url":
        clean_text = raw_text.strip()
        parsed = urllib.parse.urlparse(clean_text)
        scheme = (parsed.scheme or "").lower()

        # Prohibit dangerous execution schemes
        if scheme in {"javascript", "data", "file", "intent", "blob", "about", "vbscript"}:
            return {
                "payload_type": "url",
                "raw_payload": clean_text[:500],
                "verdict": "HIGH RISK",
                "risk_level": "HIGH RISK",
                "legacy_verdict": "dangerous",
                "risk_score": 100,
                "threat_indicators": [f"Prohibited / dangerous URI scheme '{scheme}:' detected. Automated script execution or local protocol handlers are blocked."],
                "recommendations": ["Do not execute or open this payload. It attempts to trigger script execution or local device handlers."],
                "englishSummary": f"Blocked dangerous URI scheme ({scheme}:)",
                "hindiSummary": f"असुरक्षित URI स्कीम ब्लॉक की गई ({scheme}:)",
            }

        if scheme and scheme not in {"http", "https"}:
            return {
                "payload_type": "url",
                "raw_payload": clean_text[:500],
                "verdict": "SUSPICIOUS",
                "risk_level": "SUSPICIOUS",
                "legacy_verdict": "suspicious",
                "risk_score": 60,
                "threat_indicators": [f"Non-standard URI scheme '{scheme}:' detected."],
                "recommendations": ["Review the protocol carefully before opening in an external application."],
                "englishSummary": f"Non-standard URI scheme ({scheme}:)",
                "hindiSummary": f"गैर-मानक URI स्कीम ({scheme}:)",
            }

        canonical_url, hostname = normalize_url(raw_text)
        scanner = ResearchScanner(canonical_url)
        scanner.target_url = canonical_url
        link_report = scanner.execute_scan()

        raw_v = (link_report.get("verdict") or "").lower()
        if raw_v in {"dangerous", "malicious"} or link_report.get("overall_status") == "Blocked":
            verdict = "HIGH RISK"
        elif raw_v in {"suspicious", "risky"}:
            verdict = "SUSPICIOUS"
        elif raw_v in {"safe", "clean", "trusted"}:
            verdict = "NO KNOWN THREAT DETECTED"
        else:
            verdict = "INSUFFICIENT EVIDENCE"

        risk_score = link_report.get("risk_score", 50)
        threats = link_report.get("threat_indicators", []) or link_report.get("threats", [])

        recommendations = list(link_report.get("recommendations", []))
        recommendations.insert(0, "ZERO-TRUST ADVISORY: Review destination profile below. Do not visit if unverified.")

        return {
            "payload_type": "url",
            "raw_payload": raw_text,
            "verdict": verdict,
            "risk_level": verdict,
            "legacy_verdict": "dangerous" if verdict == "HIGH RISK" else ("suspicious" if verdict == "SUSPICIOUS" else "safe"),
            "risk_score": risk_score,
            "action_url": canonical_url,
            "parsed_data": {
                "target_url": canonical_url,
                "hostname": hostname,
                "overall_status": link_report.get("overall_status"),
                "is_trusted": link_report.get("overall_status") == "Trusted",
                "malicious_engines": link_report.get("malicious_count", 0),
                "total_engines": link_report.get("total_engines", 0),
            },
            "threat_indicators": threats,
            "recommendations": recommendations,
            "technical_checks": link_report.get("technical_checks", []),
            "englishSummary": link_report.get("englishSummary", f"URL destination: {hostname}"),
            "hindiSummary": link_report.get("hindiSummary", f"वेबसाइट लिंक: {hostname}"),
        }

    elif payload_type == "upi":
        res = analyze_upi_payload(raw_text)
        res["raw_payload"] = raw_text
        return res

    elif payload_type == "wifi":
        res = analyze_wifi_payload(raw_text)
        res["raw_payload"] = raw_text
        return res

    elif payload_type == "contact":
        res = analyze_contact_payload(raw_text)
        res["raw_payload"] = raw_text
        return res

    else:
        res = analyze_text_payload(raw_text)
        res["raw_payload"] = raw_text
        return res
