import concurrent.futures
import re
import time
import traceback
import logging
from typing import Dict, List, Literal, Optional

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
    "gemini-2.5-flash",
    "gemini-1.5-flash",
    "gemini-1.5-pro",
]
MAX_RETRIES = 1          # fail fast — 1 retry per model before moving on
BASE_BACKOFF_SECONDS = 0.5
GEMINI_TIMEOUT_SECONDS = 38  # hard per-attempt ceiling (frontend fires at 45s)
MAX_HISTORY_INJECT = 8   # cap history at 8 turns to control prompt size

# ─── Fallback messages when all models are exhausted ─────────────────────────
QUOTA_FALLBACK_EN = (
    "CyberSaathi is experiencing high traffic right now. Please try again shortly.\n\n"
    "In the meantime, for immediate safety:\n"
    "• Stop any ongoing payments immediately\n"
    "• Call 1930 if it's financial fraud\n"
    "• Save screenshots and evidence\n"
    "• File a report on cybercrime.gov.in"
)
QUOTA_FALLBACK_HI = (
    "CyberSaathi पर अभी बहुत अधिक ट्रैफ़िक है। कृपया कुछ देर बाद पुनः प्रयास करें।\n\n"
    "तब तक, तुरंत सुरक्षा के लिए:\n"
    "• चल रहे भुगतान तुरंत रोकें\n"
    "• वित्तीय धोखाधड़ी होने पर 1930 पर कॉल करें\n"
    "• स्क्रीनशॉट और सबूत सुरक्षित रखें\n"
    "• cybercrime.gov.in पर रिपोर्ट दर्ज करें"
)

# ─── Lean core system prompt (always sent) ───────────────────────────────────
# Keep this small. Incident-specific detail is injected per-request only when
# the classifier fires, keeping the default prompt under ~200 tokens.

SYSTEM_PROMPT = """\
You are CyberSaathi, a cyber safety assistant for Indian users.

RULES:
- Calm, direct, technically accurate. No filler, no drama.
- Victims aren't foolish — scams are engineered. Treat them as capable adults.
- Under stress: lead with the single most urgent action. Max 3 steps.
- Never say: "Stay strong", "You got this", "I'm sorry this happened", "As an AI".
- Do not repeat guidance already given in this conversation.
- Max 140 words. Under urgency: max 90 words.

LANGUAGE:
- Reply in the language the user actually wrote in.
- English message → English reply. Hindi/Devanagari → Hindi. Mixed → Hinglish.

APPROACH:
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
                     "money gone", "paise gaye", "paise kate", "payment", "transferred",
                     "otp shared", "otp diya", "qr code", "qr scan"],
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


# ─── Language Auto-Detection ─────────────────────────────────────────────────

def _detect_message_language(message: str, ui_language: str) -> str:
    """Detect message language from content; fall back to ui_language."""
    # Count Devanagari characters — strong signal for Hindi
    devanagari_count = sum(1 for c in message if '\u0900' <= c <= '\u097f')
    if devanagari_count >= 3:
        return "हिंदी"

    # Common Hinglish markers: Roman script Hindi words
    hinglish_markers = [
        "mera", "meri", "kya", "karo", "kiya", "hua", "gaya", "nahi", "nahin",
        "paisa", "paise", "bhai", "yaar", "please", "help karo", "batao",
        "liya", "diya", "liya", "kar", "ho", "hai", "tha", "thi",
    ]
    lowered = message.lower()
    hinglish_hits = sum(1 for w in hinglish_markers if w in lowered)
    if hinglish_hits >= 2:
        # Treat Hinglish as Hindi for response purpose
        return "हिंदी"

    # Default to UI language preference
    return ui_language


def _gemini_reply(message: str, history: List[ChatTurn], language: str,
                  incident: Optional[Dict] = None) -> str:

    if not settings.gemini_api_key:
        return (
            "Tell me what happened and I'll walk you through it. If it's financial fraud: stop all payments now, call 1930, and save the transaction ID as evidence."
            if language == "English"
            else "बताइए क्या हुआ — मैं कदम-दर-कदम मदद करूँगा/करूँगी। अगर पैसा गया है: भुगतान तुरंत रोकें, 1930 पर कॉल करें, और transaction ID सुरक्षित रखें。"
        )

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
        f"Language: {language}\n"
        f"{incident_hint}"
        f"\nConversation:\n{turns}\nuser: {message}\nassistant:"
    )
    prompt_chars = len(prompt)
    logger.info(
        "[CHAT] Prompt built: chars=%d (~%d tokens), history_turns=%d",
        prompt_chars, prompt_chars // 4, len(capped_history),
    )

    # ── Retry loop with model fallback + hard per-attempt timeout ──
    last_exception: Optional[Exception] = None

    for model_name in MODEL_FALLBACK_CHAIN:
        for attempt in range(MAX_RETRIES + 1):
            try:
                logger.info("[GEMINI] model=%s attempt=%d", model_name, attempt + 1)
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
                    continue

                logger.info("[GEMINI] OK model=%s attempt=%d ms=%d chars=%d",
                            model_name, attempt + 1, api_ms, len(text))
                return text.strip()

            except Exception as exc:
                last_exception = exc
                is_quota = _is_quota_error(exc)
                is_timeout = isinstance(exc, TimeoutError)
                logger.warning(
                    "[GEMINI] %s model=%s attempt=%d: %s",
                    "QUOTA" if is_quota else ("TIMEOUT" if is_timeout else "ERROR"),
                    model_name, attempt + 1, exc,
                )

                if is_quota or is_timeout:
                    break  # skip retries, move to next model immediately

                if attempt < MAX_RETRIES:
                    delay = BASE_BACKOFF_SECONDS * (2 ** attempt)
                    time.sleep(delay)

    logger.error("[GEMINI] ALL MODELS EXHAUSTED. Last error: %s", last_exception)
    return QUOTA_FALLBACK_EN if language == "English" else QUOTA_FALLBACK_HI


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
            actions.append({"type": "navigate", "target": "email", "label": "Check Email Breaches"})

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
    return {
        "mentions_url": bool(re.search(r"https?://|\blink\b|\burl\b|phish", lowered)),
        "mentions_email": bool(re.search(r"\bemail\b|mail|breach|leak", lowered)),
        "mentions_app": bool(re.search(r"\bapp\b|apk|play\s?store|package", lowered)),
        "mentions_deepfake": bool(re.search(r"deepfake|ai image|synthetic image|fake photo|fake video", lowered)),
        "mentions_complaint": bool(re.search(r"\bcomplaint\b|\bfir\b|cybercrime\.gov", lowered)),
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

        # Resolve base language from UI preference
        ui_lang = payload.language
        if ui_lang == "Hinglish":
            ui_lang = "हिंदी"

        # Detect actual message language — override UI preference if needed
        detected_lang = _detect_message_language(payload.message, ui_lang)
        logger.info("[CHAT] Language: ui=%s detected=%s", payload.language, detected_lang)

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

        is_emergency_raw = (
            emotion == "crisis"
            or (incident and incident.get("urgency") in ("critical", "high"))
        )

        if not isinstance(is_emergency_raw, bool):
            logger.warning("[CHAT] Classifier returned invalid type %s for is_emergency. Defaulting to False.", type(is_emergency_raw).__name__)
            is_emergency = False
        else:
            is_emergency = bool(is_emergency_raw)

        context = _extract_scan_context(payload.message)
        if emotion == "crisis":
            response_text = CRISIS_RESPONSE_EN if detected_lang == "English" else CRISIS_RESPONSE_HI
        else:
            response_text = _gemini_reply(payload.message, payload.history or [], detected_lang, incident)
            logger.info("[CHAT] Response generated (len=%d)", len(response_text))
            prefix = _grounded_assist_prefix(context, detected_lang)
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
        quick_actions = _quick_actions(payload.message, emotion, incident)

        # Add tool quick-action buttons only when strongly contextual and not already covered
        existing_targets = {a.get("target") for a in quick_actions}
        if context["mentions_deepfake"] and "deepfake" not in existing_targets:
            quick_actions.append({"type": "navigate", "target": "deepfake", "label": "Open Deepfake Detector"})
        if context["mentions_url"] and "scanner" not in existing_targets and not incident:
            # Only suggest link scanner when there's no higher-priority incident action
            quick_actions.append({"type": "navigate", "target": "scanner", "label": "Scan Suspicious Link"})
        if context["mentions_email"] and "email" not in existing_targets and incident and incident.get("type") == "account_hack":
            quick_actions.append({"type": "navigate", "target": "email", "label": "Check Email Breaches"})
        if context["mentions_app"] and "app-check" not in existing_targets and not incident:
            quick_actions.append({"type": "navigate", "target": "app-check", "label": "Verify App"})
        quick_actions = quick_actions[:4]

        total_ms = int((time.monotonic() - t_start) * 1000)
        logger.info("[CHAT] Done: total_ms=%d emotion=%s incident=%s emergency=%s",
                    total_ms, emotion, incident["type"] if incident else "none", is_emergency)
        return ChatResponse(
            response=response_text,
            emotion=emotion,
            suggestedAction=suggested,
            englishSummary="Follow safe steps and avoid making decisions in panic.",
            hindiSummary="सुरक्षित कदम अपनाएँ और घबराहट में कोई निर्णय न लें।",
            quickActions=quick_actions,
            incidentType=incident["type"] if incident else None,
            urgencyLevel=incident["urgency"] if incident else None,
            isEmergency=is_emergency,
        )
    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        is_quota = _is_quota_error(e)
        logger.error("[CHAT] %s error in /chat: %s", "QUOTA" if is_quota else "UNEXPECTED", error_msg)
        logger.error(traceback.format_exc())

        fallback_text = (
            QUOTA_FALLBACK_EN if is_quota
            else "I'm sorry, something went wrong on my end. Please try again in a moment."
        )
        return ChatResponse(
            response=fallback_text,
            emotion="normal",
            suggestedAction="Please try again shortly.",
            englishSummary="Temporary issue. Please retry.",
            hindiSummary="अस्थायी समस्या। कृपया पुनः प्रयास करें।",
            quickActions=[],
            isEmergency=False,
        )
