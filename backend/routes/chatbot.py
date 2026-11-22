import concurrent.futures
from enum import Enum
import re
import time
import traceback
import logging
from typing import Dict, List, Literal, Optional, Tuple

from google import genai
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger("veyron-backend")

from config import firebase_store, settings
from routes.utils import CRISIS_RESPONSE_EN, CRISIS_RESPONSE_HI, detect_emotion, iso_now, sha_key

router = APIRouter(tags=["chatbot"])

# ─── Model fallback chain (in priority order) ────────────────────────────────
MODEL_FALLBACK_CHAIN = [
    "gemini-flash-lite-latest",
    "gemini-3.5-flash-lite",
    "gemini-3.5-flash",
    "gemini-3.8-flash",
    "gemini-2.5-flash",
]
MAX_RETRIES = 0          # fail fast directly to next fallback model in chain
BASE_BACKOFF_SECONDS = 0.5
GEMINI_TIMEOUT_SECONDS = 12   # bounded per-model attempt ceiling
MAX_TOTAL_API_TIMEOUT = 22    # total loop timeout ceiling (frontend fires at 45s)
MAX_HISTORY_INJECT = 6        # cap history to 6 turns to keep prompt token latency low

# In-process model cooldown cache: model_name -> unblock_timestamp
_model_cooldowns: Dict[str, float] = {}

def get_model_cooldowns() -> Dict[str, float]:
    """Return active model cooldowns for diagnostics and testing."""
    return dict(_model_cooldowns)

def reset_model_cooldowns():
    """Clear all active model cooldowns."""
    _model_cooldowns.clear()

def _is_model_in_cooldown(model_name: str) -> bool:
    return time.monotonic() < _model_cooldowns.get(model_name, 0.0)

def _set_model_cooldown(model_name: str, err_kind: 'GeminiErrorKind'):
    now = time.monotonic()
    if err_kind == GeminiErrorKind.QUOTA_EXHAUSTED:
        _model_cooldowns[model_name] = now + 120.0  # 2 minutes for daily quota
    elif err_kind == GeminiErrorKind.RATE_LIMITED:
        _model_cooldowns[model_name] = now + 25.0   # 25 seconds for burst limit
    elif err_kind == GeminiErrorKind.MODEL_UNAVAILABLE:
        _model_cooldowns[model_name] = now + 1800.0 # 30 minutes for deprecated/404 models
    elif err_kind in (GeminiErrorKind.TIMEOUT, GeminiErrorKind.SERVICE_UNAVAILABLE):
        _model_cooldowns[model_name] = now + 15.0   # 15 seconds for transient load


# ─── Error Taxonomy & Classification ──────────────────────────────────────────

class GeminiErrorKind(str, Enum):
    RATE_LIMITED = "RATE_LIMITED"
    QUOTA_EXHAUSTED = "QUOTA_EXHAUSTED"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    NETWORK_ERROR = "NETWORK_ERROR"
    TIMEOUT = "TIMEOUT"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    INVALID_REQUEST = "INVALID_REQUEST"
    INTERNAL_ERROR = "INTERNAL_ERROR"


def classify_gemini_error(exc: Exception) -> GeminiErrorKind:
    """Classify exceptions from Gemini SDK into distinct operational error kinds."""
    if isinstance(exc, (TimeoutError, concurrent.futures.TimeoutError)):
        return GeminiErrorKind.TIMEOUT

    err_str = str(exc).lower()

    if "timeout" in err_str or "timed out" in err_str:
        return GeminiErrorKind.TIMEOUT

    # Authentication / Authorization errors (401, 403, invalid API key, permission denied)
    if any(sig in err_str for sig in ["401", "403", "api_key", "permission_denied", "unauthenticated", "forbidden"]):
        return GeminiErrorKind.AUTHENTICATION_FAILED

    # Model not found or deprecated (404)
    if any(sig in err_str for sig in ["404", "not_found", "not found", "is not supported", "no longer available"]):
        return GeminiErrorKind.MODEL_UNAVAILABLE

    # Upstream service overloaded or unavailable (503)
    if any(sig in err_str for sig in ["503", "service_unavailable", "high demand", "overloaded"]):
        return GeminiErrorKind.SERVICE_UNAVAILABLE

    # Rate limiting vs Quota exhaustion (429 / resource_exhausted)
    if any(sig in err_str for sig in ["429", "resource_exhausted", "too many requests"]):
        # Check if it is daily / project quota vs momentary burst rate limit
        if any(q_sig in err_str for q_sig in ["quota exceeded", "per day", "daily", "limit: 20", "free_tier_requests", "day limit"]):
            return GeminiErrorKind.QUOTA_EXHAUSTED
        return GeminiErrorKind.RATE_LIMITED

    # Network connectivity issues
    if any(sig in err_str for sig in ["connection", "network", "unreachable", "gaierror", "socket", "dns"]):
        return GeminiErrorKind.NETWORK_ERROR

    # Bad request / Invalid input (400)
    if any(sig in err_str for sig in ["400", "invalid_argument", "bad request"]):
        return GeminiErrorKind.INVALID_REQUEST

    return GeminiErrorKind.INTERNAL_ERROR


def _is_greeting_or_meta(message: str) -> bool:
    """Detect if the message is a casual greeting, polite phrase, or meta-question."""
    lowered = message.strip().lower()

    # Common conversational greetings & pleasantries
    greetings = [
        "hi", "hello", "hey", "namaste", "namaskar", "good morning",
        "good afternoon", "good evening", "how are you", "kese ho",
        "kaise ho", "kya haal hai", "whats up", "what's up", "wassup",
        "kaise ho aap", "kya chal raha hai", "sup"
    ]
    if any(lowered == g or lowered.startswith(g + " ") or lowered.startswith(g + "!") or lowered.startswith(g + "?") for g in greetings):
        return True

    # Meta questions about high traffic, system capacity, or identity
    meta_signals = [
        "traffic", "high traffic", "matlab kya", "kya ho raha hai",
        "who are you", "what are you", "what is cybersaathi", "kaun ho",
        "tum kaun ho", "aap kaun hain", "traffic kyu", "traffic kyon"
    ]
    if any(sig in lowered for sig in meta_signals):
        return True

    return False


def _generate_fallback_response(
    error_kind: GeminiErrorKind,
    language: str,
    has_active_incident: bool,
    is_greeting_or_meta: bool = False,
    user_message: str = "",
) -> str:
    """Generate an honest, context-aware operational response when AI models are unavailable."""
    is_hindi = language == "हिंदी"
    is_hinglish = language == "Hinglish"

    # If the user asked specifically about high traffic or system status:
    lowered = user_message.lower() if user_message else ""
    if "traffic" in lowered or "matlab" in lowered or "kya ho raha" in lowered:
        if is_hinglish:
            return (
                "High traffic ka matlab hai ki bohot saare users ek saath CyberSaathi se connect kar rahe hain, "
                "jisse server par temporary load hai. Main aapki digital suraksha ke liye yahan hoon — please kuch lamhon mein dobara message karein."
            )
        if is_hindi:
            return (
                "हाई ट्रैफ़िक (High Traffic) का मतलब है कि इस समय बहुत सारे उपयोगकर्ता एक साथ CyberSaathi से संपर्क कर रहे हैं, "
                "जिससे सर्वर की क्षमता पर अस्थायी दबाव है। आपकी सुरक्षा से संबंधित सामान्य सहायता सक्रिय है — कृपया कुछ पलों में पुनः प्रयास करें।"
            )
        return (
            "High traffic means CyberSaathi is currently experiencing a high volume of simultaneous requests, "
            "temporarily exceeding processing capacity. Core safety services remain active — please try again in a few moments."
        )

    # If greeting in fallback mode:
    if is_greeting_or_meta and not has_active_incident:
        if is_hinglish:
            return (
                "Namaste! Main CyberSaathi hoon — aapki digital suraksha saathi. "
                "Currently AI service high demand handle kar rahi hai. Aap apna cyber safety sawal likhein, main jald hi fully ready ho jaungi."
            )
        if is_hindi:
            return (
                "नमस्ते! मैं CyberSaathi हूँ — आपकी साइबर सुरक्षा साथी। "
                "वर्तमान में AI सेवा उच्च अनुरोधों के कारण कुछ व्यस्त है। आप अपना साइबर सुरक्षा प्रश्न लिख सकते हैं, मैं आपकी सहायता के लिए तैयार हूँ।"
            )
        return (
            "Hello! I am CyberSaathi, your digital safety companion. "
            "Our AI assistant is momentarily experiencing high demand. Please feel free to share your cybersecurity question and try again shortly."
        )

    # Base operational status messages based on classified error
    if error_kind == GeminiErrorKind.RATE_LIMITED:
        if is_hinglish:
            base_msg = "CyberSaathi par is waqt requests ki sankhya zyada hai. Kripya thoda intezar karke dobara try karein. Main yahan aapki help ke liye hoon."
        elif is_hindi:
            base_msg = "CyberSaathi पर इस समय अनुरोधों की संख्या अधिक है। कृपया कुछ क्षण प्रतीक्षा करके पुनः प्रयास करें। मैं आपकी सहायता के लिए तत्पर हूँ।"
        else:
            base_msg = "CyberSaathi is currently handling high request volume. Please wait a moment and try again."
    elif error_kind == GeminiErrorKind.QUOTA_EXHAUSTED:
        if is_hinglish:
            base_msg = "CyberSaathi ki current AI processing limit temporarily reach ho chuki hai. Service jald hi normal ho jayegi."
        elif is_hindi:
            base_msg = "CyberSaathi की वर्तमान AI प्रसंस्करण सीमा पूरी हो चुकी है। सेवा जल्द ही सामान्य हो जाएगी।"
        else:
            base_msg = "CyberSaathi has reached its AI processing capacity for the current window. Service will resume shortly."
    elif error_kind == GeminiErrorKind.AUTHENTICATION_FAILED:
        if is_hinglish:
            base_msg = "CyberSaathi AI service temporarily maintenance mein hai. Kripya kuch der baad try karein."
        elif is_hindi:
            base_msg = "CyberSaathi AI सेवा इस समय अस्थायी रखरखाव में है। कृपया कुछ देर बाद प्रयास करें।"
        else:
            base_msg = "CyberSaathi AI service is temporarily undergoing maintenance. Please check back shortly."
    elif error_kind == GeminiErrorKind.TIMEOUT:
        if is_hinglish:
            base_msg = "Request process hone mein zyada time lag gaya. Kripya apna message dobara send karein."
        elif is_hindi:
            base_msg = "अनुरोध प्रोसेस होने में अधिक समय लग गया। कृपया अपना संदेश पुनः भेजें।"
        else:
            base_msg = "The request took longer than expected to process. Please send your message again."
    elif error_kind in (GeminiErrorKind.SERVICE_UNAVAILABLE, GeminiErrorKind.MODEL_UNAVAILABLE):
        if is_hinglish:
            base_msg = "CyberSaathi AI service currently update ya temporary busy phase mein hai. Kripya kuch der baad dobara koshish karein."
        elif is_hindi:
            base_msg = "CyberSaathi की AI सेवा अपडेट या अस्थायी व्यस्तता के दौर में है। कृपया कुछ देर बाद पुनः प्रयास करें।"
        else:
            base_msg = "CyberSaathi AI service is currently updating or under high demand. Please try again in a few moments."
    else:
        if is_hinglish:
            base_msg = "CyberSaathi AI service se connect karne mein temporary problem aa rahi hai. Kripya thodi der baad try karein."
        elif is_hindi:
            base_msg = "CyberSaathi AI सेवा से कनेक्ट करने में अस्थायी समस्या आ रही है। कृपया कुछ देर बाद पुनः प्रयास करें।"
        else:
            base_msg = "CyberSaathi is experiencing a temporary connection issue with the AI service. Please try again shortly."

    # ONLY append emergency cybercrime instructions if an active incident or emergency exists!
    if has_active_incident:
        if is_hinglish:
            emergency_block = (
                "\n\nImmediate safety steps:\n"
                "• Financial fraud hone par turant 1930 par call karein\n"
                "• Apne bank se contact karke payment freeze karwayen\n"
                "• Sabhi screenshots, messages aur UPI Ref ID secure rakhein\n"
                "• cybercrime.gov.in par formal complaint darj karein"
            )
        elif is_hindi:
            emergency_block = (
                "\n\nतत्काल सुरक्षा के लिए महत्वपूर्ण कदम:\n"
                "• वित्तीय धोखाधड़ी होने पर तुरंत 1930 पर कॉल करें\n"
                "• अपने बैंक से संपर्क कर लेन-देन को फ्रीज़ (रोकें) कराएं\n"
                "• सभी स्क्रीनशॉट, संदेश और UPI Ref ID सुरक्षित रखें\n"
                "• cybercrime.gov.in पर औपचारिक रिपोर्ट दर्ज करें"
            )
        else:
            emergency_block = (
                "\n\nIn the meantime, for your immediate protection:\n"
                "• If this is financial fraud, call the National Cyber Helpline at 1930 immediately\n"
                "• Contact your bank right away to freeze further transactions\n"
                "• Preserve all screenshots, transaction IDs, and chat messages as evidence\n"
                "• File an official complaint at cybercrime.gov.in"
            )
        return base_msg + emergency_block

    return base_msg


# ─── Lean core system prompt (always sent) ───────────────────────────────────

SYSTEM_PROMPT = """\
You are CyberSaathi, a calm, professional, and knowledgeable female cybersecurity assistant for Indian users.

PERSONA & GENDER IDENTITY (MANDATORY):
- CyberSaathi is strictly a FEMALE digital safety companion and assistant (आपकी साइबर सुरक्षा साथी / सहायिका).
- When speaking in Hindi or Hinglish, you MUST ALWAYS use feminine grammatical self-references:
  - Say "मैं आपकी सहायता कर सकती हूँ" (NEVER "कर सकता हूँ").
  - Say "मैं आपको समझाऊँगी" (NEVER "समझाऊँगा").
  - Say "मैं आपको बताऊँगी" (NEVER "बताऊँगा").
  - Say "मैं आपकी साइबर सुरक्षा साथी हूँ" (NEVER "आपका सहायक" or "सहायक").
  - In Hinglish: say "Main aapki help kar sakti hoon" (NEVER "kar sakta hoon"), "Main bataungi" (NEVER "bataunga"), "Main aapki saathi hoon" (NEVER "aapka saathi").
- Do NOT infer, assume, or change the gender of the user. Always address the user with respectful gender-neutral honorifics ("आप", "आपकी", "आपका").
- Tone: Calm, supportive, professional, direct, technically accurate. No filler, no panic.

LANGUAGE POLICY (STRICT PRECEDENCE):
- You MUST reply in the exact target language assigned for this turn:
  1. English input -> Reply completely in English.
  2. Hindi (Devanagari) input -> Reply completely in Hindi (Devanagari script).
  3. Hinglish (Roman script) input -> Reply completely in natural Roman-script Hinglish.
  4. Explicit language instructions (e.g., "in English", "in Hindi", "हिंदी में") ALWAYS take absolute precedence over previous conversation turns and UI settings.
- Never reply in Hindi to an English message.
- Never reply in Devanagari to a Roman-script Hinglish message.

RULES:
- Calm, direct, technically accurate. No filler, no drama.
- Victims aren't foolish — scams are engineered. Treat them as capable adults.
- Under stress: lead with the single most urgent action. Max 3 steps.
- Never say: "Stay strong", "You got this", "I'm sorry this happened", "As an AI".
- Do not repeat guidance already given in this conversation.
- Max 140 words. Under urgency: max 90 words.

CONVERSATIONAL & GREETINGS:
- When the user greets (e.g. "hi", "hello", "how are you"), reply warmly and concisely in 1-2 sentences. Introduce yourself as CyberSaathi, Veyron's cyber safety companion, and ask how you can help with their digital safety. Do NOT dump emergency instructions, numbers, or crime steps unless an incident is mentioned.

EDUCATIONAL & GENERAL QUESTIONS:
- When asked conceptual or educational questions (e.g. "what is phishing?", "how does 2FA work?", "explain ransomware"): provide a clear, concise, informative breakdown with practical safety habits. Do NOT treat the user as an active victim or tell them to stop payments or call 1930 unless they explicitly report a crime.

META & STATUS QUESTIONS:
- When asked meta questions (e.g. "high traffic matlab kya ho raha hai", "how do you work?"): explain clearly in the user's language without panic or irrelevant helpline triggers.

APPROACH (for reported incidents):
- First message about an incident: ask 1-2 targeted questions. Don't dump a checklist.
- Once you have enough context: give concrete, ordered steps.
- Conversation history is provided. Do not re-ask questions already answered.

EVIDENCE (when incident is active):
- Never delete messages, transactions, or conversations.
- Screenshot everything before blocking.
- Save UPI ref IDs, transaction IDs, caller numbers.

TOOLS (only when directly relevant):
- Suspicious link → suggest Link Scanner
- Email compromised → suggest Breach Checker
- Suspicious app → suggest App Checker
- Fake image/video → suggest Deepfake Detector
- Filing complaint → mention Complaint Hub
"""

# ─── Per-incident flow scripts (injected only when classifier fires) ──────────
# These are NOT sent on every message — only when _classify_incident matches.

INCIDENT_SCRIPTS: Dict[str, str] = {
    "upi_fraud": (
        "[UPI/Payment Fraud]\n"
        "Ask (if not yet answered): Which app? How much? When? OTP/PIN shared?\n"
        "If same day: Call bank NOW to freeze. Call 1930 (golden hour). Do NOT send more money.\n"
        "Evidence: UPI ref ID, transaction screenshot, sender UPI ID.\n"
        "Report: cybercrime.gov.in → Financial Fraud."
    ),
    "account_hack": (
        "[Account Compromise]\n"
        "Ask (if not yet answered): Which platform? Email still accessible? Ransom demand?\n"
        "If email accessible: Change email password first, then platform recovery.\n"
        "Recovery: Instagram → 'Need more help?'; Facebook → Compromised Account; Gmail → account.google.com/recovery.\n"
        "After recovery: revoke app permissions, enable 2FA.\n"
        "Report: platform help center + cybercrime.gov.in if threats involved."
    ),
    "phishing": (
        "[Phishing/Fake Link]\n"
        "Ask (if not yet answered): Did you click? Enter credentials?\n"
        "If credentials entered: change passwords on all accounts sharing that password.\n"
        "If only clicked: device scan + clear cookies.\n"
        "Report: forward phishing SMS to 1909 (TRAI). File on cybercrime.gov.in."
    ),
    "sextortion": (
        "[Sextortion/Image Abuse]\n"
        "CALM FIRST. This is a crime — not the victim's fault.\n"
        "Do NOT pay. Paying escalates demands. Do NOT delete conversations.\n"
        "Screenshot everything (profile, threats, payment demands) before blocking.\n"
        "Report: cybercrime.gov.in → Women/Child Safety. Call 1091 (women). iCall: 9152987821.\n"
        "Legal: IT Act 66E, IPC 354C. FIR is your right."
    ),
    "investment_scam": (
        "[Investment/Job Scam]\n"
        "Ask (if not yet answered): Which platform? How contacted? How much invested?\n"
        "Do NOT invest more to 'recover' losses — that's the next trap.\n"
        "Evidence: app screenshots, chat history, payment receipts.\n"
        "Report: cybercrime.gov.in → Financial Fraud. RBI for banking transactions."
    ),
    "cyberbullying": (
        "[Cyberbullying/Harassment]\n"
        "Ask (if not yet answered): Which platform? Physical threat?\n"
        "Block and restrict. Make account private.\n"
        "Evidence: Screenshots with timestamps.\n"
        "Report: platform tool → cybercrime.gov.in. iCall: 9152987821 for support."
    ),
}


# ─── Incident Classification ─────────────────────────────────────────────────

INCIDENT_PATTERNS = {
    "upi_fraud": {
        "keywords": ["upi", "paytm", "phonepe", "gpay", "google pay", "bhim", "money sent",
                     "money gone", "paise gaye", "paise kate", "cut gaye", "kat gaye", "payment", "transferred",
                     "bank account", "bank se", "otp shared", "otp diya", "qr code", "qr scan"],
        "urgency": "high",
        "label_en": "UPI/Payment Fraud",
        "label_hi": "UPI/भुगतान धोखाधड़ी",
    },
    "account_hack": {
        "keywords": ["hacked", "hack", "account hacked", "login nahi", "can't login",
                     "password changed", "someone logged in", "account stolen",
                     "instagram hack", "facebook hack", "gmail hack"],
        "urgency": "high",
        "label_en": "Account Compromise",
        "label_hi": "अकाउंट हैक",
    },
    "phishing": {
        "keywords": ["phishing", "fake link", "suspicious link", "clicked link", "fake site",
                     "entered password", "fake email", "kyc update", "bank verification"],
        "urgency": "medium",
        "label_en": "Phishing Attack",
        "label_hi": "फिशिंग हमला",
    },
    "sextortion": {
        "keywords": ["sextortion", "nude", "intimate", "blackmail", "photo threat",
                     "video threat", "private photo", "morphed", "leaked", "leak karunga",
                     "viral karunga"],
        "urgency": "critical",
        "label_en": "Sextortion/Image Abuse",
        "label_hi": "सेक्सटॉर्शन/छवि दुरुपयोग",
    },
    "investment_scam": {
        "keywords": ["investment", "trading", "crypto scam", "forex", "ponzi",
                     "double money", "guaranteed returns", "task scam", "earning app",
                     "telegram earning", "part time job"],
        "urgency": "medium",
        "label_en": "Investment/Job Scam",
        "label_hi": "निवेश/नौकरी धोखाधड़ी",
    },
    "cyberbullying": {
        "keywords": ["bullying", "bully", "harassment", "threat", "abuse", "stalking",
                     "trolling", "hate", "gaali", "dhamki", "defamation"],
        "urgency": "medium",
        "label_en": "Cyberbullying/Harassment",
        "label_hi": "साइबरबुलिंग/उत्पीड़न",
    },
}


def _classify_incident(message: str, history: List["ChatTurn"]) -> Optional[Dict]:
    """Classify the incident type from message + recent history context."""
    # Build context from recent messages for better classification
    context_parts = [message]
    for turn in (history or [])[-4:]:
        context_parts.append(turn.content)
    context = " ".join(context_parts).lower()

    best_match = None
    best_score = 0

    for incident_id, pattern in INCIDENT_PATTERNS.items():
        score = sum(1 for kw in pattern["keywords"] if kw in context)
        if score > best_score:
            best_score = score
            best_match = {
                "type": incident_id,
                "urgency": pattern["urgency"],
                "label_en": pattern["label_en"],
                "label_hi": pattern["label_hi"],
                "confidence": min(1.0, score * 0.25),
            }

    # Require at least 1 keyword match
    return best_match if best_score >= 1 else None


# ─── Models ──────────────────────────────────────────────────────────────────

class ChatTurn(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=2000)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    history: Optional[List[ChatTurn]] = Field(default_factory=list)
    language: Literal["English", "हिंदी", "Hinglish"] = "English"


class ChatResponse(BaseModel):
    response: str
    emotion: Literal["calm", "panic", "crisis", "normal"]
    suggestedAction: str
    englishSummary: str
    hindiSummary: str
    quickActions: List[dict] = Field(default_factory=list)
    incidentType: Optional[str] = None
    urgencyLevel: Optional[str] = None
    isEmergency: bool = False
    fallbackType: Optional[str] = None


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _suggested_action(emotion: str, incident: Optional[Dict] = None) -> str:
    if incident:
        urgency = incident.get("urgency", "low")
        inc_type = incident.get("type", "")
        if urgency == "critical":
            return "Do NOT pay or comply with threats. Preserve all evidence. Report immediately."
        if urgency == "high" and "upi" in inc_type:
            return "Call your bank NOW to freeze the transaction. Then call 1930."
        if urgency == "high":
            return "Secure your accounts immediately. Change passwords, enable 2FA."

    mapping = {
        "crisis": "Call mental health helpline now and stay with trusted person.",
        "panic": "Take 3 deep breaths, stop payments immediately, preserve evidence.",
        "calm": "Follow step-by-step reporting and security cleanup.",
        "normal": "Run safety checks and enable account protections.",
    }
    return mapping.get(emotion, mapping["normal"])


def _is_quota_error(exc: Exception) -> bool:
    """Detect 429 / RESOURCE_EXHAUSTED quota errors from Gemini SDK."""
    err_str = str(exc).lower()
    err_type = type(exc).__name__.lower()
    quota_signals = ["429", "resource_exhausted", "quota", "rate limit", "rate_limit", "too many requests"]
    return any(sig in err_str or sig in err_type for sig in quota_signals)


# ─── Language Classifier & Female Persona Enforcement ────────────────────────

HINGLISH_WORDS = {
    # Pronouns & demonstratives
    "aap", "aapko", "aapka", "aapki", "aapke", "mera", "meri", "mere", "mujhe", "mujhko",
    "hum", "hamara", "hamari", "hamare", "yeh", "ye", "woh", "wo", "iska", "iski", "iske",
    "uske", "uski", "uska", "unka", "unki", "unke", "apna", "apne", "apni",
    # Question words
    "kya", "kyu", "kyun", "kaise", "kese", "kab", "kaha", "kahan", "kaun", "kisko",
    "kitna", "kitne", "kitni",
    # Conjunctions & particles
    "nahi", "nahin", "na", "mat", "aur", "lekin", "par", "magar", "ya", "toh", "bhi", "hi",
    # Verbs, auxiliaries & status words
    "hai", "hain", "ho", "hoon", "hu", "tha", "thi", "the", "hoga", "hogi", "hoge",
    "raha", "rahi", "rahe", "gaya", "gayi", "gaye", "aaya", "aayi", "aaye", "hua", "hui", "hue",
    "karo", "kare", "karen", "karein", "karna", "karti", "karta", "kiya", "batao", "bataiye",
    "batana", "samjhao", "samjhaye", "dekhna", "dekho", "chahiye", "bolo", "bhejo", "bheja",
    "sakta", "sakti", "sakte", "paise", "paisa", "khata", "khate", "dhokha", "shikayat",
    "madad", "matlab", "dhyan", "rakho", "rakhein", "hoti", "hota", "hote"
}

ENGLISH_COMMON_WORDS = {
    "the", "is", "are", "am", "was", "were", "have", "has", "had", "do", "does", "did",
    "can", "could", "will", "would", "shall", "should", "may", "might", "must", "this",
    "that", "these", "those", "what", "when", "where", "which", "who", "whom", "whose",
    "why", "how", "i", "you", "he", "she", "it", "we", "they", "my", "your", "his",
    "her", "its", "our", "their", "me", "him", "us", "them", "and", "but", "or",
    "because", "as", "if", "than", "at", "by", "for", "from", "in", "into", "of",
    "off", "on", "onto", "out", "over", "to", "up", "with", "about", "against", "between",
    "through", "during", "before", "after", "above", "below", "down", "under", "again",
    "further", "then", "once", "here", "there", "all", "any", "both", "each", "few",
    "more", "most", "other", "some", "such", "no", "nor", "not", "only", "own", "same",
    "so", "too", "very", "just", "now", "hello", "hi", "hey", "please", "help", "thanks",
    "thank", "good", "morning", "afternoon", "evening", "night", "fine", "well", "great",
    "explain", "tell", "check", "verify", "scam", "fraud", "hacked", "phishing", "link",
    "money", "account", "bank", "password", "call", "message", "safe", "danger", "security"
}


def resolve_message_language(message: str, history: Optional[List[ChatTurn]] = None, ui_language: str = "English") -> str:
    """
    Deterministic message language resolver with strict precedence:
    1. Explicit language directive (e.g., 'in english', 'explain in hindi', 'हिंदी में')
    2. Devanagari script presence -> 'हिंदी'
    3. Hinglish vs English detection on Latin alphabet
    4. Ambiguous input inherits from previous user message or fallback to ui_language
    """
    msg_strip = message.strip()
    if not msg_strip:
        return ui_language if ui_language in ("English", "हिंदी", "Hinglish") else "English"

    lowered = msg_strip.lower()

    # 1. Explicit Language Directives
    if re.search(r'\b(in english|reply in english|answer in english|respond in english|speak in english|english please|english me|english mein)\b', lowered):
        return "English"
    if re.search(r'\b(in hindi|reply in hindi|answer in hindi|respond in hindi|speak in hindi|hindi please|hindi me|hindi mein|हिंदी में|हिंदी में बताओ|हिंदी में समझाइए|हिंदी में जवाब)\b', lowered):
        return "हिंदी"
    if re.search(r'\b(in hinglish|reply in hinglish|answer in hinglish|respond in hinglish|hinglish please|hinglish me|hinglish mein)\b', lowered):
        return "Hinglish"

    # 2. Devanagari Script Analysis
    devanagari_chars = sum(1 for c in msg_strip if '\u0900' <= c <= '\u097f')
    if devanagari_chars >= 2 or (len(msg_strip) <= 6 and devanagari_chars >= 1):
        return "हिंदी"

    # 3. Tokenize Latin text
    tokens = [w for w in re.findall(r'[a-zA-Z]+', lowered)]
    if not tokens:
        return ui_language if ui_language in ("English", "हिंदी", "Hinglish") else "English"

    # Match tokens (ignoring 'sathi' if preceded by 'cyber')
    hinglish_tokens = []
    for i, tok in enumerate(tokens):
        if tok == "sathi" and i > 0 and tokens[i - 1] in ("cyber", "cybersaathi"):
            continue
        if tok in HINGLISH_WORDS:
            hinglish_tokens.append(tok)

    english_tokens = [tok for tok in tokens if tok in ENGLISH_COMMON_WORDS]

    h_count = len(hinglish_tokens)
    e_count = len(english_tokens)

    # Hinglish dominance
    if h_count >= 2 and h_count >= e_count:
        return "Hinglish"
    if h_count >= 1 and e_count == 0:
        return "Hinglish"

    # English dominance
    if e_count >= 1:
        return "English"

    # 4. Short ambiguous messages ("ok", "sure", "yes", "no")
    if history:
        for turn in reversed(history):
            if turn.role == "user" and turn.content.strip():
                prev_lang = resolve_message_language(turn.content, None, ui_language)
                if prev_lang:
                    return prev_lang

    return ui_language if ui_language in ("English", "हिंदी", "Hinglish") else "English"


# Backward compatibility helper
def _detect_message_language(message: str, ui_language: str = "English") -> str:
    return resolve_message_language(message, history=None, ui_language=ui_language)


def enforce_female_persona(text: str, language: str) -> str:
    """Ensure CyberSaathi's self-references in Hindi/Hinglish use feminine grammar."""
    if language == "हिंदी":
        # Replace first-person masculine self-references: मैं ... सकता हूँ -> मैं ... सकती हूँ
        # (Avoid \b with Devanagari combining marks)
        text = re.sub(r'((?:^|[\s,!?।])मैं[^।?!]*?)\s+सकता\s+हूँ', r'\1 सकती हूँ', text)
        text = re.sub(r'((?:^|[\s,!?।])मैं[^।?!]*?)\s+करूँगा', r'\1 करूँगी', text)
        text = re.sub(r'((?:^|[\s,!?।])मैं[^।?!]*?)\s+बताऊँगा', r'\1 बताऊँगी', text)
        text = re.sub(r'((?:^|[\s,!?।])मैं[^।?!]*?)\s+समझाऊँगा', r'\1 समझाऊँगी', text)
        text = re.sub(r'((?:^|[\s,!?।])मैं[^।?!]*?)\s+दूँगा', r'\1 दूँगी', text)
        # Assistant identity nouns
        text = re.sub(r'((?:^|[\s,!?।]))आपका\s+(साइबर\s+सुरक्षा|डिजिटल\s+सुरक्षा)?\s*सहायक', r'\1आपकी \2 साथी', text)
        text = re.sub(r'((?:^|[\s,!?।]))एक\s+(साइबर\s+सुरक्षा|डिजिटल\s+सुरक्षा)?\s*सहायक', r'\1एक \2 साथी', text)
        text = re.sub(r'((?:^|[\s,!?।]))आपका\s+सहायक', r'\1आपकी साथी', text)
        text = re.sub(r'\bआपका\s+साइबर\s+सुरक्षा\s+साथी\b', r'आपकी साइबर सुरक्षा साथी', text)
        text = re.sub(r'\bआपका\s+डिजिटल\s+सुरक्षा\s+साथी\b', r'आपकी डिजिटल सुरक्षा साथी', text)
    elif language == "Hinglish":
        # Replace first-person masculine self-references in Roman Hinglish
        text = re.sub(r'(\bmain\b[^.?!]*?)\bkar\s+sakta\s+hoon\b', r'\1kar sakti hoon', text, flags=re.IGNORECASE)
        text = re.sub(r'(\bmain\b[^.?!]*?)\bsakta\s+hoon\b', r'\1sakti hoon', text, flags=re.IGNORECASE)
        text = re.sub(r'(\bmain\b[^.?!]*?)\bbataunga\b', r'\1bataungi', text, flags=re.IGNORECASE)
        text = re.sub(r'(\bmain\b[^.?!]*?)\bkarunga\b', r'\1karungi', text, flags=re.IGNORECASE)
        text = re.sub(r'(\bmain\b[^.?!]*?)\bsamjhaunga\b', r'\1samjhaungi', text, flags=re.IGNORECASE)
        text = re.sub(r'(\bmain\b[^.?!]*?)\bdoonga\b', r'\1doongi', text, flags=re.IGNORECASE)
        text = re.sub(r'\baapka\s+(cyber|digital\s+safety\s+)?saathi\b', r'aapki \1saathi', text, flags=re.IGNORECASE)
    return text


def _gemini_reply(
    message: str,
    history: List[ChatTurn],
    language: str,
    incident: Optional[Dict] = None,
    is_greeting_or_meta: bool = False,
) -> Tuple[str, Optional[str]]:

    if not settings.gemini_api_key:
        fallback = _generate_fallback_response(
            GeminiErrorKind.AUTHENTICATION_FAILED,
            language,
            has_active_incident=bool(incident),
            is_greeting_or_meta=is_greeting_or_meta,
            user_message=message,
        )
        fallback = enforce_female_persona(fallback, language)
        return fallback, GeminiErrorKind.AUTHENTICATION_FAILED.value

    client = genai.Client(api_key=settings.gemini_api_key)

    # ── Cap history to control prompt size ──
    capped_history = history[-MAX_HISTORY_INJECT:]
    turns = "\n".join([f"{h.role}: {h.content}" for h in capped_history])

    # ── Build incident hint: inject flow script only when classifier fires ──
    incident_hint = ""
    if incident:
        inc_type = incident.get("type", "")
        urgency = incident.get("urgency", "low")
        # Inject the compact per-incident script (not in base system prompt)
        script = INCIDENT_SCRIPTS.get(inc_type, "")
        if script:
            incident_hint = f"\n{script}\n"
        if urgency in ("critical", "high"):
            incident_hint += "URGENCY: Lead with the single most time-critical action first.\n"

    # ── Conversation state: avoid re-asking answered questions ──
    asked_topics: List[str] = []
    assistant_turns = [h.content.lower() for h in capped_history if h.role == "assistant"]
    checks = [
        ("platform/app", lambda t: "which app" in t or "which platform" in t or "कौन सा ऐप" in t),
        ("OTP/PIN", lambda t: "otp" in t or "pin" in t),
        ("email access", lambda t: "email" in t or "ईमेल" in t),
        ("ransom", lambda t: "ransom" in t or "demand" in t),
        ("evidence", lambda t: "screenshot" in t or "evidence" in t or "स्क्रीनशॉट" in t),
    ]
    for topic, fn in checks:
        if any(fn(t) for t in assistant_turns):
            asked_topics.append(topic)
    if asked_topics:
        incident_hint += f"Already addressed: {', '.join(asked_topics)}. Do not repeat.\n"

    prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"TARGET_RESPONSE_LANGUAGE: {language}\n"
        f"INSTRUCTION: You must formulate your entire answer in {language}. "
        f"If {language} is 'Hinglish', use natural Roman script Hinglish only (do not use Devanagari script). "
        f"If {language} is 'हिंदी', use Devanagari script only. "
        f"If {language} is 'English', use English only. "
        f"Remember CyberSaathi is strictly FEMALE: use feminine self-reference grammar (कर सकती हूँ / kar sakti hoon).\n"
        f"{incident_hint}"
        f"\nConversation:\n{turns}\nuser: {message}\nassistant:"
    )
    prompt_chars = len(prompt)
    logger.info(
        "[CHAT] Prompt built: chars=%d (~%d tokens), history_turns=%d",
        prompt_chars, prompt_chars // 4, len(capped_history),
    )

    # ── Fast model fallback loop with in-process cooldown cache ──
    t_loop_start = time.monotonic()
    last_exception: Optional[Exception] = None

    # Filter out models currently in cooldown to avoid wasting round-trips on dead endpoints
    active_models = [m for m in MODEL_FALLBACK_CHAIN if not _is_model_in_cooldown(m)]
    if not active_models:
        # If all models are in cooldown, reset cache to avoid deadlock
        reset_model_cooldowns()
        active_models = list(MODEL_FALLBACK_CHAIN)

    for model_name in active_models:
        # Enforce overall loop ceiling
        if time.monotonic() - t_loop_start > MAX_TOTAL_API_TIMEOUT:
            logger.warning("[GEMINI] Overall API timeout ceiling (%ds) reached. Skipping remaining models.", MAX_TOTAL_API_TIMEOUT)
            break

        try:
            logger.info("[GEMINI] model=%s attempt=1", model_name)
            t_api_start = time.monotonic()

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    lambda m=model_name, p=prompt: client.models.generate_content(
                        model=m, contents=p
                    )
                )
                try:
                    result = future.result(timeout=GEMINI_TIMEOUT_SECONDS)
                except concurrent.futures.TimeoutError:
                    raise TimeoutError(
                        f"Gemini {model_name} exceeded {GEMINI_TIMEOUT_SECONDS}s ceiling"
                    )

            api_ms = int((time.monotonic() - t_api_start) * 1000)
            text = getattr(result, "text", None)

            if not text:
                last_exception = ValueError(f"Empty response from {model_name}")
                logger.warning("[GEMINI] Empty response model=%s ms=%d", model_name, api_ms)
                _set_model_cooldown(model_name, GeminiErrorKind.INVALID_REQUEST)
                continue

            logger.info("[GEMINI] OK model=%s ms=%d chars=%d",
                        model_name, api_ms, len(text))
            enforced_text = enforce_female_persona(text.strip(), language)
            return enforced_text, None

        except Exception as exc:
            last_exception = exc
            err_kind = classify_gemini_error(exc)
            logger.warning(
                "[GEMINI] %s model=%s: %s",
                err_kind.value,
                model_name, exc,
            )
            # Record cooldown so subsequent requests don't waste time on this model
            _set_model_cooldown(model_name, err_kind)

    logger.error("[GEMINI] ALL MODELS EXHAUSTED. Last error: %s", last_exception)
    last_err_kind = classify_gemini_error(last_exception) if last_exception else GeminiErrorKind.SERVICE_UNAVAILABLE
    fallback_text = _generate_fallback_response(
        last_err_kind,
        language,
        has_active_incident=bool(incident),
        is_greeting_or_meta=is_greeting_or_meta,
        user_message=message,
    )
    fallback_text = enforce_female_persona(fallback_text, language)
    return fallback_text, last_err_kind.value


def _quick_actions(message: str, emotion: str, incident: Optional[Dict] = None) -> List[dict]:
    """Generate context-aware quick action buttons."""
    lowered = message.lower()
    actions: List[dict] = []

    # Incident-specific actions
    if incident:
        inc_type = incident.get("type", "")
        urgency = incident.get("urgency", "low")

        if urgency in ("critical", "high"):
            actions.append({"type": "call", "target": "1930", "label": "Call Cyber Helpline 1930"})

        if "upi" in inc_type or "investment" in inc_type:
            actions.append({"type": "navigate", "target": "complaints", "label": "File Complaint"})
            actions.append({"type": "link", "target": "https://cybercrime.gov.in", "label": "cybercrime.gov.in"})

        if "sextortion" in inc_type:
            actions.append({"type": "call", "target": "9152987821", "label": "Call iCall Support"})
            actions.append({"type": "navigate", "target": "complaints", "label": "Report to Cyber Cell"})

        if "account_hack" in inc_type:
            actions.append({"type": "navigate", "target": "spam", "label": "Check Email Breaches"})

        if "phishing" in inc_type:
            actions.append({"type": "navigate", "target": "scanner", "label": "Scan Suspicious Link"})
    else:
        # Fallback: keyword-based actions
        if any(x in lowered for x in ["scam", "fraud", "upi", "money", "bank", "otp", "phishing"]):
            actions.append({"type": "navigate", "target": "complaints", "label": "Open Complaint Hub"})
            actions.append({"type": "link", "target": "https://cybercrime.gov.in", "label": "Report on cybercrime.gov.in"})
        if emotion in {"panic", "crisis"}:
            actions.append({"type": "call", "target": "1930", "label": "Call Cyber Helpline 1930"})

    return actions[:4]


def _extract_scan_context(message: str) -> Dict[str, bool]:
    lowered = message.lower()

    # Check for actual URLs or explicit link verification intent
    has_explicit_url = bool(re.search(r"https?://|www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", lowered))
    has_link_intent = bool(re.search(r"\b(check|scan|verify|test|is\s+this|received\s+a)\s+(this\s+)?(link|url|website|site)\b", lowered))

    # Check for actual email address or explicit email breach check intent
    has_explicit_email = bool(re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", lowered))
    has_email_intent = bool(re.search(r"\b(check|pwned|breached|leaked|verify)\s+(my\s+)?email\b", lowered))

    # Check for explicit app checking intent (APK, download link, suspicious app)
    has_app_intent = bool(re.search(r"\b(apk|fake\s+app|malicious\s+app|verify\s+app|check\s+app|suspicious\s+app|downloaded\s+an?\s+app)\b", lowered))

    # Check for deepfake / media inspection intent
    has_deepfake_intent = bool(re.search(r"\b(deepfake|ai\s+generated\s+(photo|image|video)|synthetic\s+media|morphed\s+(photo|video|face)|fake\s+(photo|video|face))\b", lowered))

    # Check for complaint filing intent
    has_complaint_intent = bool(re.search(r"\b(file|lodge|register)\s+(a\s+)?(complaint|fir|report)\b|cybercrime\.gov", lowered))

    return {
        "mentions_url": has_explicit_url or has_link_intent,
        "mentions_email": has_explicit_email or has_email_intent,
        "mentions_app": has_app_intent,
        "mentions_deepfake": has_deepfake_intent,
        "mentions_complaint": has_complaint_intent,
    }


def _grounded_assist_prefix(context: Dict[str, bool], language: str) -> str:
    """Inject tool suggestions naturally — only when strongly relevant."""
    tips_en: List[str] = []
    tips_hi: List[str] = []

    # Only add tip if the context signals a direct need for the tool
    if context["mentions_url"]:
        tips_en.append("Paste that link into the Link Scanner to check it before opening.")
        tips_hi.append("उस लिंक को Link Scanner में चेक करें — खोलने से पहले।")
    if context["mentions_email"]:
        tips_en.append("Run your email through the Breach Checker to see if it was leaked.")
        tips_hi.append("Breach Checker में अपना ईमेल जांचें — देखें कहीं leak हुआ तो नहीं।")
    if context["mentions_app"]:
        tips_en.append("Verify the app in App Checker before installing or trusting it.")
        tips_hi.append("App Checker से ऐप की जाँच करें — install करने से पहले।")
    if context["mentions_deepfake"]:
        tips_en.append("Upload that image or video to the Deepfake Detector for a forensic screen.")
        tips_hi.append("उस image/video को Deepfake Detector में upload करके जाँचें।")
    if context["mentions_complaint"]:
        tips_en.append("The Complaint Hub has a step-by-step filing guide and evidence checklist.")
        tips_hi.append("Complaint Hub में complaint दर्ज करने की पूरी guide है।")

    if not tips_en:
        return ""

    # Return as inline addition, not a labeled section
    if language == "English":
        return "\n".join(tips_en) + "\n\n"
    return "\n".join(tips_hi) + "\n\n"


# ─── Main Endpoint ───────────────────────────────────────────────────────────

@router.post("/chat")
def chat_with_cybersaathi(payload: ChatRequest):
    try:
        logger.info("[CHAT] Request: lang=%s, msg_len=%d", payload.language, len(payload.message))
        t_start = time.monotonic()

        emotion = detect_emotion(payload.message)

        # Resolve target language using deterministic classifier with clear precedence
        target_lang = resolve_message_language(payload.message, payload.history or [], payload.language)
        logger.info("[CHAT] Language: ui=%s resolved=%s", payload.language, target_lang)

        t_classify = time.monotonic()
        incident = _classify_incident(payload.message, payload.history or [])
        logger.info("[CHAT] Classify: result=%s ms=%d",
                    incident["type"] if incident else "none",
                    int((time.monotonic() - t_classify) * 1000))
        if incident:
            logger.info(
                "[CHAT] Incident detected: type=%s urgency=%s confidence=%.2f",
                incident["type"], incident["urgency"], incident["confidence"]
            )

        greeting_or_meta = _is_greeting_or_meta(payload.message)

        is_emergency = bool(
            emotion == "crisis"
            or bool(incident and incident.get("urgency") in ("critical", "high"))
        )

        context = _extract_scan_context(payload.message)
        fallback_type: Optional[str] = None

        if emotion == "crisis":
            response_text = CRISIS_RESPONSE_EN if target_lang == "English" else CRISIS_RESPONSE_HI
        else:
            response_text, fallback_type = _gemini_reply(
                payload.message,
                payload.history or [],
                target_lang,
                incident,
                is_greeting_or_meta=greeting_or_meta,
            )
            logger.info("[CHAT] Response generated (len=%d, fallback=%s)", len(response_text), fallback_type)

            # Only append grounded assistant tool prefix if context matches and not purely conversational
            if not greeting_or_meta:
                prefix = _grounded_assist_prefix(context, target_lang)
                if prefix:
                    response_text = response_text + "\n\n" + prefix.strip()

        # Persist to Firebase
        chat_id = sha_key(payload.message + iso_now())
        if firebase_store.enabled:
            firebase_store.save_document(
                "chat_history",
                chat_id,
                {
                    "message": payload.message,
                    "history": [x.model_dump() for x in payload.history or []],
                    "language": payload.language,
                    "response": response_text,
                    "emotion": emotion,
                    "incidentType": incident["type"] if incident else None,
                    "urgency": incident["urgency"] if incident else None,
                    "createdAt": iso_now(),
                },
            )

        suggested = _suggested_action(emotion, incident)
        if greeting_or_meta and not incident:
            suggested = "Ask any cyber safety or digital protection question."

        quick_actions = _quick_actions(payload.message, emotion, incident)

        # For conversational queries without an incident, offer exploration navigation
        if greeting_or_meta and not incident:
            quick_actions = [
                {"type": "navigate", "target": "scanner", "label": "Scan a Link"},
                {"type": "navigate", "target": "deepfake", "label": "Deepfake Detector"},
                {"type": "navigate", "target": "spam", "label": "Email Breach Check"},
            ]
        else:
            # Add tool quick-action buttons only when strongly contextual and not already covered
            existing_targets = {a.get("target") for a in quick_actions}
            if context["mentions_deepfake"] and "deepfake" not in existing_targets:
                quick_actions.append({"type": "navigate", "target": "deepfake", "label": "Open Deepfake Detector"})
            if context["mentions_url"] and "scanner" not in existing_targets and not incident:
                quick_actions.append({"type": "navigate", "target": "scanner", "label": "Scan Suspicious Link"})
            if context["mentions_email"] and "spam" not in existing_targets and incident and incident.get("type") == "account_hack":
                quick_actions.append({"type": "navigate", "target": "spam", "label": "Check Email Breaches"})
            if context["mentions_app"] and "app" not in existing_targets and not incident:
                quick_actions.append({"type": "navigate", "target": "app", "label": "Verify App"})

        quick_actions = quick_actions[:4]

        total_ms = int((time.monotonic() - t_start) * 1000)
        logger.info("[CHAT] Done: total_ms=%d emotion=%s incident=%s emergency=%s fallback=%s",
                    total_ms, emotion, incident["type"] if incident else "none", is_emergency, fallback_type)

        summary_en = "Follow safe steps and avoid making decisions in panic." if incident else "Ask any cyber safety or digital protection question."
        summary_hi = "सुरक्षित कदम अपनाएँ और घबराहट में कोई निर्णय न लें।" if incident else "साइबर सुरक्षा से जुड़ा कोई भी प्रश्न पूछें।"

        return ChatResponse(
            response=response_text,
            emotion=emotion,
            suggestedAction=suggested,
            englishSummary=summary_en,
            hindiSummary=summary_hi,
            quickActions=quick_actions,
            incidentType=incident["type"] if incident else None,
            urgencyLevel=incident["urgency"] if incident else None,
            isEmergency=is_emergency,
            fallbackType=fallback_type,
        )
    except Exception as e:
        err_kind = classify_gemini_error(e)
        error_msg = f"{type(e).__name__}: {str(e)}"
        logger.error("[CHAT] %s error in /chat: %s", err_kind.value, error_msg)
        logger.error(traceback.format_exc())

        fallback_text = _generate_fallback_response(
            err_kind,
            payload.language,
            has_active_incident=False,
            is_greeting_or_meta=_is_greeting_or_meta(payload.message),
            user_message=payload.message,
        )
        return ChatResponse(
            response=fallback_text,
            emotion="normal",
            suggestedAction="Please try again shortly.",
            englishSummary="Temporary issue. Please retry.",
            hindiSummary="अस्थायी समस्या। कृपया पुनः प्रयास करें।",
            quickActions=[],
            isEmergency=False,
            fallbackType=err_kind.value,
        )
