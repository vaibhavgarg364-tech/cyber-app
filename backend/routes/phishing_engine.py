import re
import urllib.parse
import hashlib
import numpy as np
import os
from PIL import Image
from typing import Any, Dict, List, Optional, Tuple, Set

PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    pass

OCR_AVAILABLE = False
try:
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    try:
        import easyocr
        OCR_AVAILABLE = True
    except ImportError:
        pass

def compute_phash(image_path_or_obj) -> str:
    try:
        if isinstance(image_path_or_obj, str):
            if not os.path.exists(image_path_or_obj):
                return "0000000000000000"
            img = Image.open(image_path_or_obj)
        else:
            img = image_path_or_obj
        # Convert to grayscale and resize to 8x8
        img = img.convert('L').resize((8, 8), Image.Resampling.LANCZOS)
        pixels = list(img.getdata())
        avg = sum(pixels) / 64
        # Build hash bits
        bits = "".join(["1" if p >= avg else "0" for p in pixels])
        hex_val = hex(int(bits, 2))[2:].zfill(16)
        return hex_val
    except Exception:
        return "0000000000000000"

def hamming_distance(hash1: str, hash2: str) -> int:
    try:
        val1 = int(hash1, 16)
        val2 = int(hash2, 16)
        diff = val1 ^ val2
        return bin(diff).count("1")
    except Exception:
        return 64

def run_real_ocr(img_path: str) -> str:
    if not os.path.exists(img_path):
        return ""
    try:
        import pytesseract
        return pytesseract.image_to_string(Image.open(img_path))
    except Exception:
        try:
            import easyocr
            reader = easyocr.Reader(['en'])
            results = reader.readtext(img_path)
            return " ".join([res[1] for res in results])
        except Exception:
            return ""


# Brand database profiles with specific typosquat patterns and official domains
BRAND_DATABASE = {
    "amazon": {
        "name": "Amazon",
        "domains": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de"],
        "keywords": ["amazon", "prime", "aws"],
        "title_patterns": [r"\bamazon\b"],
        "logo_signatures": ["amazon-logo", "amazon_logo", "nav-sprite"],
        "typo_pattern": r"amaz[0o]n"
    },
    "google": {
        "name": "Google",
        "domains": ["google.com", "google.co.in", "accounts.google.com", "mail.google.com", "youtube.com"],
        "keywords": ["google", "gmail", "gpay", "youtube"],
        "title_patterns": [r"\bgoogle\b", r"\bgmail\b"],
        "logo_signatures": ["google-logo", "google_logo", "logo_gmail"],
        "typo_pattern": r"g[0o]{2}gle"
    },
    "paypal": {
        "name": "PayPal",
        "domains": ["paypal.com", "paypal.in", "paypal.co.uk"],
        "keywords": ["paypal", "venmo"],
        "title_patterns": [r"\bpaypal\b"],
        "logo_signatures": ["paypal-logo", "paypal_logo", "pp-logo"],
        "typo_pattern": r"payp[a4][l1i]"
    },
    "apple": {
        "name": "Apple",
        "domains": ["apple.com", "icloud.com", "itunes.apple.com"],
        "keywords": ["apple", "icloud", "iphone", "macbook"],
        "title_patterns": [r"\bapple\b", r"\bicloud\b"],
        "logo_signatures": ["apple-logo", "apple_logo", "apple_icon"],
        "typo_pattern": r"app[1le]"
    },
    "meta": {
        "name": "Meta",
        "domains": ["facebook.com", "instagram.com", "meta.com", "whatsapp.com"],
        "keywords": ["facebook", "instagram", "whatsapp", "meta", "messenger"],
        "title_patterns": [r"\bfacebook\b", r"\binstagram\b", r"\bwhatsapp\b"],
        "logo_signatures": ["facebook_logo", "instagram_logo", "whatsapp_logo"],
        "typo_pattern": r"f[a4]c[e3]b[0o]{2}k"
    },
    "phonepe": {
        "name": "PhonePe",
        "domains": ["phonepe.com"],
        "keywords": ["phonepe", "ybl"],
        "title_patterns": [r"\bphonepe\b"],
        "logo_signatures": ["phonepe_logo", "phonepe-logo"],
        "typo_pattern": r"ph[0o]n[e3]p[e3]"
    },
    "gpay": {
        "name": "Google Pay",
        "domains": ["pay.google.com", "google.com"],
        "keywords": ["gpay", "google pay"],
        "title_patterns": [r"\bgpay\b", r"\bgoogle pay\b"],
        "logo_signatures": ["gpay_logo", "gpay-logo", "google-pay"],
        "typo_pattern": r"gp[a4]y"
    },
    "upi": {
        "name": "UPI",
        "domains": ["upi.org.in", "npci.org.in"],
        "keywords": ["upi", "npci", "bhim"],
        "title_patterns": [r"\bupi\b", r"\bbhim\b", r"\bnpci\b"],
        "logo_signatures": ["upi-logo", "upi_logo", "bhim-logo"],
        "typo_pattern": r"up[i1]"
    },
    
    # Patched Microsoft Brands ecosystem (PATCH 1)
    "microsoft": {
        "name": "Microsoft",
        "domains": ["microsoft.com", "live.com", "outlook.com", "login.microsoftonline.com", "office.com"],
        "keywords": ["microsoft", "ms-login", "azure", "office365"],
        "title_patterns": [r"\bmicrosoft\b"],
        "logo_signatures": ["microsoft-logo", "microsoft_logo", "ms-logo"],
        "typo_pattern": r"rnicrosoft|micr[0o]s[0o]ft|m[1l]crosoft|ms-login"
    },
    "windows": {
        "name": "Windows",
        "domains": ["microsoft.com"],
        "keywords": ["windows", "win10", "win11"],
        "title_patterns": [r"\bwindows\b"],
        "logo_signatures": ["windows-logo", "windows_logo"],
        "typo_pattern": r"w[1l]nd[0o]ws|vvlndows"
    },
    "office": {
        "name": "Office",
        "domains": ["office.com", "office365.com", "microsoft365.com"],
        "keywords": ["office", "office365"],
        "title_patterns": [r"\boffice\b", r"\boffice\s*365\b"],
        "logo_signatures": ["office-logo", "office_logo"],
        "typo_pattern": r"[0o]ff[1l]c[e3]-secure|[0o]ffice365"
    },
    "outlook": {
        "name": "Outlook",
        "domains": ["outlook.live.com", "outlook.office.com", "outlook.com", "hotmail.com"],
        "keywords": ["outlook", "hotmail"],
        "title_patterns": [r"\boutlook\b"],
        "logo_signatures": ["outlook-logo", "outlook_logo"],
        "typo_pattern": r"[0o]utl[0o]{2}k|0utlook"
    },
    "onedrive": {
        "name": "OneDrive",
        "domains": ["onedrive.live.com", "onedrive.com"],
        "keywords": ["onedrive"],
        "title_patterns": [r"\bonedrive\b"],
        "logo_signatures": ["onedrive-logo", "onedrive_logo"],
        "typo_pattern": r"[0o]n[e3]dr[1l]v[e3]"
    },
    "azure": {
        "name": "Azure",
        "domains": ["azure.microsoft.com", "portal.azure.com", "azure.com"],
        "keywords": ["azure"],
        "title_patterns": [r"\bazure\b"],
        "logo_signatures": ["azure-logo", "azure_logo"],
        "typo_pattern": r"az[u4]r[e3]"
    },
    "teams": {
        "name": "Teams",
        "domains": ["teams.microsoft.com", "teams.live.com"],
        "keywords": ["teams"],
        "title_patterns": [r"\bteams\b"],
        "logo_signatures": ["teams-logo", "teams_logo"],
        "typo_pattern": r"t[e3][a4]ms-verify"
    },
    "xbox": {
        "name": "Xbox",
        "domains": ["xbox.com"],
        "keywords": ["xbox"],
        "title_patterns": [r"\bxbox\b"],
        "logo_signatures": ["xbox-logo", "xbox_logo"],
        "typo_pattern": r"xb[0o]x"
    }
}

HIGH_RISK_TLDS = {"xyz", "top", "click", "zip", "rest", "country", "win", "icu", "club", "gq", "cf", "tk", "ml"}

# Levenshtein distance helper
def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

def calculate_similarity(s1: str, s2: str) -> float:
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    dist = levenshtein_distance(s1, s2)
    return 1.0 - (dist / max_len)

# Patched Confusable Character Engine (PATCH 2)
def normalize_confusables(text: str) -> str:
    text = text.lower()
    
    # Unicode homoglyphs to standard ASCII representation mapping
    homoglyphs = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'ѕ': 's', 'і': 'i', 'ј': 'j',
        'ԁ': 'd', 'ԛ': 'q', 'ѕ': 's', 'т': 't', 'ԝ': 'w', 'з': '3', 'б': '6', 'н': 'h', 'м': 'm', 'л': 'l'
    }
    for char, replacement in homoglyphs.items():
        text = text.replace(char, replacement)
        
    # Visual shape similarity mappings
    text = text.replace("rn", "m")
    text = text.replace("vv", "w")
    text = text.replace("0", "o")
    text = text.replace("1", "l")
    text = text.replace("5", "s")
    text = text.replace("@", "a")
    return text


class PhishingDetectionEngine:
    def __init__(self, url: str, html_content: str, recon_data: Dict[str, Any], crawler_data: Dict[str, Any]):
        self.url = url
        self.html_content = html_content
        self.recon_data = recon_data
        self.crawler_data = crawler_data
        
        self.parsed_url = urllib.parse.urlparse(url)
        self.domain = (self.parsed_url.hostname or "").lower()
        
        # Extracted features
        self.title = self._extract_title()
        self.forms = recon_data.get("forms", [])
        self.scripts = recon_data.get("scripts", [])
        self.headers = recon_data.get("headers", {})

    def _extract_title(self) -> str:
        match = re.search(r"<title>(.*?)</title>", self.html_content, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        return ""

    # ================= 1. Domain Intelligence Engine =================
    def analyze_domain(self) -> Dict[str, Any]:
        domain_parts = self.domain.split(".")
        main_domain = domain_parts[-2] if len(domain_parts) >= 2 else self.domain
        if len(domain_parts) >= 3 and domain_parts[-1] in ("in", "com", "org", "net", "co") and domain_parts[-2] in ("co", "org", "ac", "gov", "res"):
            main_domain = domain_parts[-3]

        typosquat_score = 0.0
        brand_match = None
        spoof_confidence = 0.0
        domain_similarity_score = 0.0
        
        # Normalize homoglyphs and confusables
        normalized_main = normalize_confusables(main_domain)
        confusable_similarity_score = 0.0

        # Check domain similarity against brand database
        for brand_key, brand_info in BRAND_DATABASE.items():
            # Check similarity to brand name itself
            sim = calculate_similarity(main_domain, brand_key)
            if sim > domain_similarity_score:
                domain_similarity_score = sim
                
            # Confusable similarity matching
            conf_sim = calculate_similarity(normalized_main, brand_key)
            if conf_sim > confusable_similarity_score:
                confusable_similarity_score = conf_sim
                
            # If normalized matches brand name but is not official domain, flag confusable typosquat
            if conf_sim >= 0.85 and not any(self.domain.endswith(d) for d in brand_info["domains"]):
                typosquat_score = max(typosquat_score, conf_sim)
                brand_match = brand_info["name"]
                spoof_confidence = max(spoof_confidence, conf_sim * 0.95)

            # Check specific typosquat substitution signature for THIS brand
            pattern = brand_info["typo_pattern"]
            if re.search(pattern, main_domain) and not any(self.domain.endswith(d) for d in brand_info["domains"]):
                typosquat_score = max(typosquat_score, 0.95)
                brand_match = brand_info["name"]
                spoof_confidence = max(spoof_confidence, 0.90)

            # Levenshtein matching
            if 0.70 <= sim < 1.0:
                if not any(self.domain.endswith(d) for d in brand_info["domains"]):
                    typosquat_score = max(typosquat_score, sim)
                    brand_match = brand_info["name"]
                    spoof_confidence = max(spoof_confidence, sim * 0.9)

        # Unicode/IDN spoofing check
        unicode_spoof = self.domain.startswith("xn--")
        
        # Suspicious subdomains check
        suspicious_subdomains_count = 0
        phish_subdomain_keywords = ["secure", "login", "verify", "update", "signin", "account", "banking"]
        for word in phish_subdomain_keywords:
            if word in self.domain:
                suspicious_subdomains_count += 1
        
        # Check nested subdomains for brand names
        for brand_key, brand_info in BRAND_DATABASE.items():
            if brand_key in domain_parts[:-2]:
                official = False
                for d in brand_info["domains"]:
                    if self.domain.endswith(d):
                        official = True
                if not official:
                    typosquat_score = max(typosquat_score, 0.85)
                    brand_match = brand_info["name"]
                    spoof_confidence = max(spoof_confidence, 0.80)

        # High risk TLD check
        tld = domain_parts[-1] if domain_parts else ""
        tld_risk = tld in HIGH_RISK_TLDS
        
        # Crypto brand keyword detection
        crypto_domain_keywords = ["wallet", "metamask", "crypto", "coin", "blockchain", "trustwallet", "ledger"]
        crypto_keyword_detected = False
        for cw in crypto_domain_keywords:
            if cw in self.domain:
                crypto_keyword_detected = True

        # Support scam domain keyword detection
        support_domain_keywords = ["support", "agent", "alert", "warning", "service", "helper"]
        support_keyword_detected = False
        for sw in support_domain_keywords:
            if sw in self.domain:
                support_keyword_detected = True

        # Calculate domain risk score
        subdomain_part = min(0.3, suspicious_subdomains_count * 0.15)
        tld_part = 0.35 if tld_risk else 0.0
        crypto_part = 0.65 if crypto_keyword_detected else 0.0
        support_part = 0.60 if support_keyword_detected else 0.0
        
        domain_risk_score = max(
            typosquat_score,
            unicode_spoof * 0.90,
            tld_part + subdomain_part,
            crypto_part,
            support_part
        )
        domain_risk_score = min(1.0, domain_risk_score)

        return {
            "domain_risk_score": domain_risk_score,
            "brand_match": brand_match,
            "spoof_confidence": spoof_confidence,
            "typosquat_score": typosquat_score,
            "unicode_spoof": unicode_spoof,
            "tld_risk": tld_risk,
            "suspicious_subdomains_count": suspicious_subdomains_count,
            "crypto_keyword_detected": crypto_keyword_detected,
            "support_keyword_detected": support_keyword_detected,
            "confusable_similarity_score": confusable_similarity_score
        }

    # ================= 2. Visual Phishing Engine =================
    def analyze_visuals(self) -> Dict[str, Any]:
        ocr_findings = []
        brand_impersonated = None
        title_mismatch = False
        
        # Part 2: Real Visual Pipeline & Screenshot check
        screenshot_path = self.crawler_data.get("screenshot_path", "")
        extracted_ocr_text = ""
        phash_val = "0000000000000000"
        visual_similarity_score = 0.0
        
        if screenshot_path and os.path.exists(screenshot_path):
            try:
                phash_val = compute_phash(screenshot_path)
                ocr_findings.append(f"Screenshot Perceptual Hash computed: {phash_val}")
                # Execute real OCR (Part 1)
                extracted_ocr_text = run_real_ocr(screenshot_path)
                if extracted_ocr_text:
                    ocr_findings.append(f"Real OCR text extracted: '{extracted_ocr_text[:100]}...'")
            except Exception as e:
                logger.error(f"[PhishingEngine] Visual analysis failed: {e}")
                
        # Degradation Fallback (Part 5): If OCR yields no text, use DOM/HTML text representation (limited to visible text if possible, but here we just use title to avoid false positives)
        ocr_text = extracted_ocr_text
        
        from routes.website_scanner import TRUSTED_DOMAINS
        is_trusted_domain = self.domain in TRUSTED_DOMAINS

        # Title and OCR text brand check
        if not is_trusted_domain:
            for brand_key, brand_info in BRAND_DATABASE.items():
                for pattern in brand_info["title_patterns"]:
                    if re.search(pattern, self.title, re.IGNORECASE) or (ocr_text and re.search(pattern, ocr_text, re.IGNORECASE)):
                        is_official = False
                        for official_domain in brand_info["domains"]:
                            if self.domain.endswith(official_domain):
                                is_official = True
                        if not is_official:
                            brand_impersonated = brand_info["name"]
                            title_mismatch = True
                            ocr_findings.append(f"Title/OCR matches brand '{brand_info['name']}' but domain is not official")

        # Logo-domain consistency
        logo_consistency_violation = False
        if not is_trusted_domain:
            for brand_key, brand_info in BRAND_DATABASE.items():
                for sig in brand_info["logo_signatures"]:
                    if sig in self.html_content.lower() or (extracted_ocr_text and sig in extracted_ocr_text.lower()):
                        is_official = False
                        for official_domain in brand_info["domains"]:
                            if self.domain.endswith(official_domain):
                                is_official = True
                        if not is_official:
                            logo_consistency_violation = True
                            ocr_findings.append(f"Contains '{brand_info['name']}' logo signatures but domain is not official")

        # Favicon lookup
        favicon_present = "rel=\"icon\"" in self.html_content or "rel=\"shortcut icon\"" in self.html_content
        favicon_hash = "None"
        if favicon_present:
            favicon_hash = hashlib.md5(self.domain.encode()).hexdigest()

        # Layout similarity (buttons, forms, OTP prompts, brand words)
        login_indicators = ["login", "signin", "sign in", "log in", "log-in", "sign-in", "enter password", "password", "otp", "credential"]
        login_detected = any(ind in ocr_text.lower() for ind in login_indicators) or any(ind in self.title.lower() for ind in login_indicators)
        
        multiple_passwords = ocr_text.lower().count("type=\"password\"") > 1 or ocr_text.lower().count("password") > 2
        otp_traps = "otp" in ocr_text.lower() or "one time password" in ocr_text.lower() or "one-time" in ocr_text.lower()
        support_scam_wording = "tech support" in ocr_text.lower() or "toll free" in ocr_text.lower() or "customer service helpline" in ocr_text.lower()
        
        support_scam_title_keywords = ["alert", "warning", "infected", "locked", "support helpline", "customer care"]
        support_scam_title_match = any(w in self.title.lower() for w in support_scam_title_keywords)

        layout_similar = login_detected and (multiple_passwords or otp_traps)
        
        visual_risk_score = max(
            title_mismatch * 0.95,
            logo_consistency_violation * 0.90,
            (login_detected and tld_risk_flag(self.domain)) * 0.75,
            (login_detected and otp_traps) * 0.80,
            layout_similar * 0.70,
            (support_scam_title_match and support_scam_wording) * 0.75
        )
        visual_risk_score = min(1.0, visual_risk_score)
        
        return {
            "visual_risk_score": visual_risk_score,
            "brand_impersonated": brand_impersonated,
            "title_mismatch": title_mismatch,
            "logo_consistency_violation": logo_consistency_violation,
            "ocr_findings": ocr_findings,
            "favicon_hash": favicon_hash,
            "login_detected": login_detected,
            "otp_traps": otp_traps,
            "support_scam": support_scam_wording,
            "support_scam_title_match": support_scam_title_match,
            "perceptual_hash": phash_val,
            "ocr_extracted_len": len(extracted_ocr_text)
        }

    # ================= 3. NLP Phishing Detector =================
    def analyze_nlp(self) -> Dict[str, Any]:
        scam_phrases = {
            "verify account": 0.25,
            "urgent action": 0.30,
            "refund": 0.20,
            "gift card": 0.25,
            "wallet verification": 0.35,
            "update KYC": 0.30,
            "account suspended": 0.30,
            "payment failed": 0.20,
            "claim reward": 0.25,
            "security alert": 0.20,
            "reset password": 0.15,
            "bank verification": 0.30
        }
        
        matches = []
        raw_score = 0.0
        for phrase, weight in scam_phrases.items():
            if re.search(r'\b' + re.escape(phrase) + r'\b', self.html_content, re.IGNORECASE):
                matches.append(phrase)
                raw_score += weight

        language_risk_score = min(1.0, raw_score * 1.5)

        # Fake support scams detection
        phone_match = re.search(r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', self.html_content)
        remote_support_words = ["anydesk", "teamviewer", "ultraviewer", "support agent", "customer service helpline", "toll free"]
        remote_support_detected = False
        for word in remote_support_words:
            if word in self.html_content.lower():
                remote_support_detected = True
                language_risk_score = max(language_risk_score, 0.90)
                matches.append(f"Remote support text: {word}")

        if phone_match:
            language_risk_score = max(language_risk_score, 0.85)
            matches.append(f"Phone support number: {phone_match.group(0)}")

        confidence = min(0.99, len(matches) * 0.25)
        
        return {
            "language_risk_score": language_risk_score,
            "confidence": confidence,
            "matched_phrases": matches,
            "phone_detected": bool(phone_match),
            "remote_support_detected": remote_support_detected
        }

    # ================= 4. Behavior Analysis =================
    def analyze_behavior(self) -> Dict[str, Any]:
        meta_refresh = "http-equiv=\"refresh\"" in self.html_content.lower()
        popup_storm = "window.open(" in self.html_content.lower() and self.html_content.lower().count("window.open") > 2
        hidden_links = "style=\"display:none\"" in self.html_content.lower() or "style=\"visibility:hidden\"" in self.html_content.lower()
        auto_download = ".apk" in self.html_content.lower() or ".exe" in self.html_content.lower()
        fullscreen_trap = "requestFullscreen" in self.html_content
        overlay_attack = "z-index" in self.html_content and "position:absolute" in self.html_content
        
        html_lower = self.html_content.lower()
        credential_trap = "type=\"password\"" in html_lower or "seed phrase" in html_lower or "secret recovery phrase" in html_lower
        support_scam_behavior = "anydesk" in html_lower or "teamviewer" in html_lower or "toll free" in html_lower or "call microsoft" in html_lower
        
        behavior_score = 0.0
        reasons = []
        if meta_refresh:
            behavior_score += 0.3
            reasons.append("Forced meta refresh redirect detected")
        if popup_storm:
            behavior_score += 0.25
            reasons.append("Popup storm coding patterns present")
        if hidden_links:
            behavior_score += 0.2
            reasons.append("Hidden stylesheet or DOM anchor link wrappers")
        if auto_download:
            behavior_score += 0.35
            reasons.append("Automated executable software payload package links (.apk/.exe)")
        if fullscreen_trap:
            behavior_score += 0.15
            reasons.append("Forced full screen lock API wrapper")
        if credential_trap:
            behavior_score = max(behavior_score, 0.85)
            reasons.append("Form credential capture block identified")
        if support_scam_behavior:
            behavior_score = max(behavior_score, 0.80)
            reasons.append("Support helpline call action indicator")
            
        behavior_score = min(1.0, behavior_score)
        
        return {
            "behavior_score": behavior_score,
            "meta_refresh": meta_refresh,
            "popup_storm": popup_storm,
            "hidden_links": hidden_links,
            "auto_download": auto_download,
            "fullscreen_trap": fullscreen_trap,
            "overlay_attack": overlay_attack,
            "reasons": reasons
        }

    # ================= 5. Page Structure Analysis =================
    def analyze_structure(self) -> Dict[str, Any]:
        form_count = len(self.forms)
        
        password_count = 0
        otp_count = 0
        card_count = 0
        wallet_count = 0
        bank_login = False
        
        html_lower = self.html_content.lower()
        
        for form in self.forms:
            for inp in form.get("inputs", []):
                t = inp.get("type", "").lower()
                n = inp.get("name", "").lower()
                if t == "password" or "password" in n:
                    password_count += 1
                if "otp" in n or "code" in n or "sms" in n:
                    otp_count += 1
                if "card" in n or "cvv" in n or "expiry" in n:
                    card_count += 1
                if "wallet" in n or "phrase" in n or "seed" in n:
                    wallet_count += 1

        if password_count == 0 and "type=\"password\"" in html_lower:
            password_count = html_lower.count("type=\"password\"")
            
        if "otp" in html_lower or "one-time" in html_lower or "one time" in html_lower:
            otp_count = max(otp_count, 1)
            
        if "card number" in html_lower or "cvv" in html_lower:
            card_count = max(card_count, 1)
            
        if "seed phrase" in html_lower or "secret recovery phrase" in html_lower:
            wallet_count = max(wallet_count, 1)
            
        if "netbanking" in html_lower or "bank login" in html_lower:
            bank_login = True

        iframe_usage = "<iframe" in html_lower
        external_scripts_count = len([s for s in self.scripts if s != "inline"])
        
        credential_harvest_score = max(
            password_count * 0.50,
            otp_count * 0.50,
            card_count * 0.60,
            wallet_count * 0.95,
            bank_login * 0.50
        )
        
        if (password_count > 0 and otp_count > 0) or wallet_count > 0 or (card_count > 0 and password_count > 0):
            credential_harvest_score = 1.0
            
        credential_harvest_score = min(1.0, credential_harvest_score)
        
        return {
            "credential_harvest_score": credential_harvest_score,
            "form_count": form_count,
            "password_count": password_count,
            "otp_count": otp_count,
            "card_count": card_count,
            "wallet_count": wallet_count,
            "bank_login": bank_login,
            "iframe_usage": iframe_usage,
            "external_scripts_count": external_scripts_count
        }

    # ================= 6. Phishing Fusion Engine =================
    def evaluate(self, threat_intel_data: Dict[str, Any]) -> Dict[str, Any]:
        domain_res = self.analyze_domain()
        visual_res = self.analyze_visuals()
        nlp_res = self.analyze_nlp()
        behavior_res = self.analyze_behavior()
        structure_res = self.analyze_structure()
        
        # Calculate reputation subscore (10%)
        reputation_score = 0.0
        vt_mal = threat_intel_data.get("virustotal_stats", {}).get("malicious", 0)
        sb_matches = len(threat_intel_data.get("safe_browsing_matches", []))
        if vt_mal > 0 or sb_matches > 0:
            reputation_score = 1.0
        elif threat_intel_data.get("blacklist_listed", False):
            reputation_score = 0.6
            
        # Fusion Weight math:
        # 25% Domain Intelligence, 20% Visual Engine, 20% NLP, 15% Behavior, 10% Credential, 10% Reputation
        final_score = (
            domain_res["domain_risk_score"] * 0.25 +
            visual_res["visual_risk_score"] * 0.20 +
            nlp_res["language_risk_score"] * 0.20 +
            behavior_res["behavior_score"] * 0.15 +
            structure_res["credential_harvest_score"] * 0.10 +
            reputation_score * 0.10
        )
        
        # PATCH 3 — Typo Boost:
        # If brand confusable similarity is high, login form exists, and suspicious TLD -> Force PHISHING RISK minimum (0.65)
        typo_boost_triggered = False
        if domain_res["confusable_similarity_score"] >= 0.75 and visual_res["login_detected"] and domain_res["tld_risk"]:
            final_score = max(final_score, 0.65)
            typo_boost_triggered = True

        # PATCH 4 — Visual Mismatch Boost:
        # If title/logo suggests configured brand name, and domain mismatch is active -> Raise visual risk score & final score
        visual_mismatch_boost = False
        if visual_res["brand_impersonated"] and visual_res["title_mismatch"]:
            visual_res["visual_risk_score"] = max(visual_res["visual_risk_score"], 0.95)
            # Re-evaluate final score with boosted visual score
            final_score = (
                domain_res["domain_risk_score"] * 0.25 +
                0.95 * 0.20 +
                nlp_res["language_risk_score"] * 0.20 +
                behavior_res["behavior_score"] * 0.15 +
                structure_res["credential_harvest_score"] * 0.10 +
                reputation_score * 0.10
            )
            visual_mismatch_boost = True

        # OVERRIDE RULE:
        # If high typosquatting score (>= 0.70) AND login detected AND visual mismatch -> Force HIGH RISK or MALICIOUS
        forced_override = False
        if domain_res["typosquat_score"] >= 0.70 and visual_res["login_detected"] and visual_res["title_mismatch"]:
            final_score = max(final_score, 0.88)
            forced_override = True

        # Verdict mapping
        from routes.website_scanner import TRUSTED_DOMAINS
        is_trusted_domain = self.domain in TRUSTED_DOMAINS

        if is_trusted_domain:
            verdict = "SAFE"
        elif final_score >= 0.88:
            verdict = "MALICIOUS"
        elif final_score >= 0.75:
            verdict = "HIGH RISK"
        elif final_score >= 0.60:
            verdict = "PHISHING RISK"
        elif final_score >= 0.35:
            verdict = "SUSPICIOUS"
        elif final_score >= 0.15:
            verdict = "LOW RISK"
        else:
            verdict = "SAFE"
            
        evidence_chain = []
        if domain_res["typosquat_score"] > 0:
            evidence_chain.append(f"Domain Typosquatting detected (matching brand: {domain_res['brand_match']})")
        if domain_res["unicode_spoof"]:
            evidence_chain.append("Unicode / IDN domain spoofing indicator present")
        if visual_res["title_mismatch"]:
            evidence_chain.append(f"Title impersonation: Title claims brand '{visual_res['brand_impersonated']}' but domain is untrusted")
        if visual_res["logo_consistency_violation"]:
            evidence_chain.append("Brand logo files found on an unauthorized third-party server")
        if nlp_res["matched_phrases"]:
            evidence_chain.append(f"NLP phishing semantic triggers matching: {', '.join(nlp_res['matched_phrases'])}")
        if behavior_res["reasons"]:
            evidence_chain.extend(behavior_res["reasons"])
        if structure_res["password_count"] > 0:
            evidence_chain.append("Credential trap: Password fields detected inside HTML forms")
        if structure_res["otp_count"] > 0:
            evidence_chain.append("OTP trap: One-Time Password / 2FA code fields discovered")
        if typo_boost_triggered:
            evidence_chain.append("Typo-boost applied: Lookalike domain with active login form on high-risk TLD")
        if forced_override:
            evidence_chain.append("Phishing fusion override triggered: High Typosquat + Login Detected + Brand Mismatch")

        return {
            "phishing_risk_score": round(float(final_score), 4),
            "verdict": verdict,
            "impersonated_brand": domain_res["brand_match"] or visual_res["brand_impersonated"] or "None",
            "evidence_chain": evidence_chain,
            "forced_override": forced_override,
            "scores": {
                "domain": round(domain_res["domain_risk_score"], 3),
                "visual": round(visual_res["visual_risk_score"], 3),
                "nlp": round(nlp_res["language_risk_score"], 3),
                "behavior": round(behavior_res["behavior_score"], 3),
                "structure": round(structure_res["credential_harvest_score"], 3),
                "reputation": round(reputation_score, 3)
            },
            "domain_details": domain_res,
            "visual_details": visual_res,
            "nlp_details": nlp_res,
            "behavior_details": behavior_res,
            "structure_details": structure_res
        }


def tld_risk_flag(domain: str) -> bool:
    parts = domain.split(".")
    if parts:
        return parts[-1] in HIGH_RISK_TLDS
    return False
