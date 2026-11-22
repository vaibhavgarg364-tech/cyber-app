import sys
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

# Ensure backend directory is in path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from main import app
from routes.chatbot import (
    GeminiErrorKind,
    classify_gemini_error,
    _generate_fallback_response,
    _is_greeting_or_meta,
    _extract_scan_context,
    _detect_message_language,
    resolve_message_language,
    enforce_female_persona,
    _classify_incident,
    ChatRequest,
    ChatTurn,
    chat_with_cybersaathi,
)


class TestChatbotApiAndClassification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_classify_gemini_error_taxonomy(self):
        """Test that all Gemini exceptions are correctly mapped to GeminiErrorKind."""
        # Timeout
        self.assertEqual(
            classify_gemini_error(TimeoutError("Operation timed out after 38s")),
            GeminiErrorKind.TIMEOUT,
        )

        # Authentication / API key
        self.assertEqual(
            classify_gemini_error(Exception("401 UNAUTHENTICATED: API_KEY_INVALID")),
            GeminiErrorKind.AUTHENTICATION_FAILED,
        )
        self.assertEqual(
            classify_gemini_error(Exception("403 PERMISSION_DENIED: The caller does not have permission")),
            GeminiErrorKind.AUTHENTICATION_FAILED,
        )

        # Model unavailable (404)
        self.assertEqual(
            classify_gemini_error(Exception("404 NOT_FOUND: models/gemini-1.5-flash is not found for API version v1beta")),
            GeminiErrorKind.MODEL_UNAVAILABLE,
        )

        # Service unavailable (503)
        self.assertEqual(
            classify_gemini_error(Exception("503 The model is overloaded. Please try again later.")),
            GeminiErrorKind.SERVICE_UNAVAILABLE,
        )

        # Daily Quota Exhaustion (429 with daily limit indicators)
        daily_quota_err = Exception(
            "429 RESOURCE_EXHAUSTED: Quota exceeded for metric: "
            "generativelanguage.googleapis.com/generate_content_free_tier_requests, limit: 20, "
            "model: gemini-2.5-flash, Generate content requests per day limit exceeded on Free Tier."
        )
        self.assertEqual(
            classify_gemini_error(daily_quota_err),
            GeminiErrorKind.QUOTA_EXHAUSTED,
        )

        # Transient Rate Limit (429 short burst)
        burst_rate_err = Exception("429 RESOURCE_EXHAUSTED: Too many requests. Please slow down.")
        self.assertEqual(
            classify_gemini_error(burst_rate_err),
            GeminiErrorKind.RATE_LIMITED,
        )

        # Network Error
        self.assertEqual(
            classify_gemini_error(ConnectionError("Connection reset by peer")),
            GeminiErrorKind.NETWORK_ERROR,
        )

        # Invalid Request (400)
        self.assertEqual(
            classify_gemini_error(Exception("400 INVALID_ARGUMENT: contents cannot be empty")),
            GeminiErrorKind.INVALID_REQUEST,
        )

    def test_fallback_response_greeting_vs_incident(self):
        """Ensure greetings during fallbacks NEVER contain emergency 1930 / stop payment advice,

        while active incidents DO contain them.
        """
        # Greeting under quota exhaustion fallback
        greeting_fallback = _generate_fallback_response(
            error_kind=GeminiErrorKind.QUOTA_EXHAUSTED,
            language="English",
            has_active_incident=False,
            is_greeting_or_meta=True,
            user_message="hi how are you",
        )
        self.assertNotIn("1930", greeting_fallback)
        self.assertNotIn("stop any ongoing payments", greeting_fallback.lower())
        self.assertIn("CyberSaathi", greeting_fallback)

        # Incident under quota exhaustion fallback
        incident_fallback = _generate_fallback_response(
            error_kind=GeminiErrorKind.QUOTA_EXHAUSTED,
            language="English",
            has_active_incident=True,
            is_greeting_or_meta=False,
            user_message="someone stole 10000 from my upi",
        )
        self.assertIn("1930", incident_fallback)
        self.assertIn("freeze", incident_fallback.lower())
        self.assertIn("cybercrime.gov.in", incident_fallback)

        # Hindi Greeting under rate limit
        greeting_hi = _generate_fallback_response(
            error_kind=GeminiErrorKind.RATE_LIMITED,
            language="हिंदी",
            has_active_incident=False,
            is_greeting_or_meta=True,
            user_message="नमस्ते",
        )
        self.assertNotIn("1930", greeting_hi)
        self.assertIn("CyberSaathi", greeting_hi)

        # Meta question "high traffic matlab kya ho raha hai"
        meta_hi = _generate_fallback_response(
            error_kind=GeminiErrorKind.RATE_LIMITED,
            language="हिंदी",
            has_active_incident=False,
            is_greeting_or_meta=True,
            user_message="high traffic matlab kya ho raha hai",
        )
        self.assertIn("हाई ट्रैफ़िक", meta_hi)
        self.assertNotIn("1930", meta_hi)

    def test_scan_context_precision(self):
        """Verify _extract_scan_context does NOT trigger false tool recommendations on educational queries."""
        # "what is phishing?" should NOT trigger mentions_url
        ctx_phish = _extract_scan_context("what is phishing?")
        self.assertFalse(ctx_phish["mentions_url"])

        # Actual URL should trigger mentions_url
        ctx_url = _extract_scan_context("Check this link: https://fake-bank-login.xyz")
        self.assertTrue(ctx_url["mentions_url"])

        # Casual app mention vs explicit app verification intent
        ctx_casual_app = _extract_scan_context("what is a mobile app?")
        self.assertFalse(ctx_casual_app["mentions_app"])

        ctx_fake_apk = _extract_scan_context("I downloaded a suspicious APK from Telegram")
        self.assertTrue(ctx_fake_apk["mentions_app"])

    def test_greeting_and_meta_detection(self):
        """Verify _is_greeting_or_meta accurately identifies greetings and meta questions."""
        self.assertTrue(_is_greeting_or_meta("hi how are you"))
        self.assertTrue(_is_greeting_or_meta("hello"))
        self.assertTrue(_is_greeting_or_meta("namaste"))
        self.assertTrue(_is_greeting_or_meta("high traffic matlab kya ho raha hai"))
        self.assertFalse(_is_greeting_or_meta("mera upi se 5000 cut gaya"))
        self.assertFalse(_is_greeting_or_meta("what is phishing?"))

    def test_language_detection(self):
        """Verify Hindi/Devanagari and Hinglish detection."""
        self.assertEqual(_detect_message_language("मेरा बैंक अकाउंट खाली हो गया", "English"), "हिंदी")
        self.assertEqual(_detect_message_language("high traffic matlab kya ho raha hai", "English"), "Hinglish")
        self.assertEqual(_detect_message_language("hi how are you", "English"), "English")

    def test_secret_hygiene_no_key_leakage(self):
        """Verify that fallback responses and classified errors NEVER expose secret tokens or keys."""
        fake_key = "AIzaSyD-secret-key-123456789"
        error_with_key = Exception(f"403 Forbidden with key {fake_key}")
        classified = classify_gemini_error(error_with_key)
        self.assertEqual(classified, GeminiErrorKind.AUTHENTICATION_FAILED)

        fallback = _generate_fallback_response(
            error_kind=classified,
            language="English",
            has_active_incident=False,
            is_greeting_or_meta=False,
        )
        self.assertNotIn(fake_key, fallback)
        self.assertNotIn("AIza", fallback)

    def test_mocked_all_models_fallback_endpoint(self):
        """Simulate all Gemini models failing with rate limit and verify polite fallback response."""
        req = ChatRequest(message="hi how are you", language="English")
        with patch("routes.chatbot.genai.Client") as mock_client:
            mock_client.return_value.models.generate_content.side_effect = Exception("429 RESOURCE_EXHAUSTED")
            resp = chat_with_cybersaathi(req)

            self.assertFalse(resp.isEmergency)
            self.assertEqual(resp.fallbackType, GeminiErrorKind.RATE_LIMITED.value)
            self.assertNotIn("1930", resp.response)
            self.assertIn("CyberSaathi", resp.response)

    def test_mocked_active_incident_fallback_endpoint(self):
        """Simulate all Gemini models failing during active fraud and verify emergency guidance."""
        req = ChatRequest(message="mera bank account se 5000 rs cut gaye fraud link se", language="English")
        with patch("routes.chatbot.genai.Client") as mock_client:
            mock_client.return_value.models.generate_content.side_effect = Exception("503 Service Unavailable")
            resp = chat_with_cybersaathi(req)

            self.assertTrue(resp.isEmergency)
            self.assertEqual(resp.fallbackType, GeminiErrorKind.SERVICE_UNAVAILABLE.value)
            self.assertIn("1930", resp.response)
            self.assertIn("cybercrime.gov.in", resp.response)

    def test_live_conversational_and_meta_smoke(self):
        """Smoke test live endpoint responses for greeting and meta inquiries."""
        # 1. Greeting
        req1 = ChatRequest(message="hi how are you", language="English")
        resp1 = chat_with_cybersaathi(req1)
        self.assertFalse(resp1.isEmergency)
        self.assertNotIn("1930", resp1.response)
        self.assertTrue(len(resp1.response) > 5)

        # 2. Meta traffic question
        req2 = ChatRequest(message="high traffic matlab kya ho raha hai", language="English")
        resp2 = chat_with_cybersaathi(req2)
        self.assertFalse(resp2.isEmergency)
        self.assertNotIn("1930", resp2.response)


    # ─── Task 1 Language & Persona Regression Suite ──────────────────────────

    def test_language_resolution_english_greeting(self):
        """English greeting resolves to English regardless of UI language."""
        lang = resolve_message_language("hello cyber Sathi how are you", [], ui_language="हिंदी")
        self.assertEqual(lang, "English")

        lang2 = resolve_message_language("Hello! I am fine, how can you help me?", [], ui_language="English")
        self.assertEqual(lang2, "English")

    def test_language_resolution_hindi_devanagari(self):
        """Devanagari text strictly resolves to Hindi."""
        lang = resolve_message_language("नमस्ते साइबर साथी, आप कैसी हैं?", [], ui_language="English")
        self.assertEqual(lang, "हिंदी")

        lang2 = resolve_message_language("क्या यह लिंक सुरक्षित है?", [], ui_language="English")
        self.assertEqual(lang2, "हिंदी")

    def test_language_resolution_roman_hinglish(self):
        """Roman script Hindi / Hinglish resolves to Hinglish."""
        lang = resolve_message_language("CyberSaathi, mujhe batao phishing kya hoti hai?", [], ui_language="English")
        self.assertEqual(lang, "Hinglish")

        lang2 = resolve_message_language("mera account hack ho gaya please madad karo", [], ui_language="English")
        self.assertEqual(lang2, "Hinglish")

    def test_language_resolution_explicit_instructions(self):
        """Explicit language directives override all other heuristics."""
        self.assertEqual(resolve_message_language("Explain phishing in English.", [], ui_language="हिंदी"), "English")
        self.assertEqual(resolve_message_language("Explain phishing in Hindi.", [], ui_language="English"), "हिंदी")
        self.assertEqual(resolve_message_language("phishing ke baare mein hindi mein batao", [], ui_language="English"), "हिंदी")
        self.assertEqual(resolve_message_language("Explain 2FA in Hinglish please.", [], ui_language="English"), "Hinglish")

    def test_language_switching_in_conversation(self):
        """Language switching midway through conversation is correctly respected."""
        history = [
            ChatTurn(role="user", content="नमस्ते, मुझे मदद चाहिए"),
            ChatTurn(role="assistant", content="नमस्ते! मैं आपकी क्या सहायता कर सकती हूँ?"),
        ]
        # User switches to English
        next_lang = resolve_message_language("Can you explain how password managers work in English?", history, ui_language="हिंदी")
        self.assertEqual(next_lang, "English")

        # Ambiguous reply like 'ok' inherits the last user language (English)
        history.append(ChatTurn(role="user", content="Can you explain how password managers work in English?"))
        history.append(ChatTurn(role="assistant", content="Password managers encrypt your passwords."))
        ambiguous_lang = resolve_message_language("ok thanks", history, ui_language="हिंदी")
        self.assertEqual(ambiguous_lang, "English")

    def test_female_persona_hindi_enforcement(self):
        """Enforces feminine self-reference in Hindi."""
        raw_hindi = "नमस्ते! मैं आपकी सहायता कर सकता हूँ और मैं आपको समझाऊँगा। मैं आपका साइबर सुरक्षा सहायक हूँ।"
        enforced = enforce_female_persona(raw_hindi, "हिंदी")
        self.assertIn("कर सकती हूँ", enforced)
        self.assertIn("समझाऊँगी", enforced)
        self.assertIn("आपकी साइबर सुरक्षा साथी", enforced)
        self.assertNotIn("कर सकता हूँ", enforced)
        self.assertNotIn("समझाऊँगा", enforced)
        self.assertNotIn("सहायक", enforced)

    def test_female_persona_hinglish_enforcement(self):
        """Enforces feminine self-reference in Hinglish."""
        raw_hinglish = "Main aapki madad kar sakta hoon. Main bataunga ki kya karna hai."
        enforced = enforce_female_persona(raw_hinglish, "Hinglish")
        self.assertIn("kar sakti hoon", enforced)
        self.assertIn("bataungi", enforced)
        self.assertNotIn("kar sakta hoon", enforced)
        self.assertNotIn("bataunga", enforced)

    def test_no_rewriting_third_person_or_quoted_masculine(self):
        """Does not rewrite masculine verbs when referring to third parties or scammers."""
        third_party_text = "स्कैमर आपको कॉल कर सकता है और पैसे मांग सकता है। वह व्यक्ति ऐसा कर सकता है।"
        enforced = enforce_female_persona(third_party_text, "हिंदी")
        self.assertEqual(enforced, third_party_text)

    def test_fallback_responses_support_all_languages_with_female_persona(self):
        """Operational fallbacks in English, Hindi, and Hinglish respect gender and language."""
        fb_en = _generate_fallback_response(GeminiErrorKind.RATE_LIMITED, "English", False)
        self.assertIn("CyberSaathi", fb_en)
        self.assertIn("high request volume", fb_en)

        fb_hi = _generate_fallback_response(GeminiErrorKind.RATE_LIMITED, "हिंदी", False)
        self.assertIn("CyberSaathi", fb_hi)
        self.assertIn("अनुरोधों की संख्या अधिक है", fb_hi)

        fb_hinglish = _generate_fallback_response(GeminiErrorKind.RATE_LIMITED, "Hinglish", False)
        self.assertIn("CyberSaathi", fb_hinglish)
        self.assertIn("requests ki sankhya zyada hai", fb_hinglish)

    def test_model_cooldown_cache_and_reset(self):
        """Verify model cooldown cache prevents repeatedly querying exhausted models and auto-resets."""
        from routes.chatbot import (
            _is_model_in_cooldown,
            _set_model_cooldown,
            reset_model_cooldowns,
            get_model_cooldowns,
            MODEL_FALLBACK_CHAIN,
        )
        reset_model_cooldowns()
        self.assertFalse(_is_model_in_cooldown("gemini-flash-lite-latest"))

        # Put model in cooldown on QUOTA_EXHAUSTED
        _set_model_cooldown("gemini-flash-lite-latest", GeminiErrorKind.QUOTA_EXHAUSTED)
        self.assertTrue(_is_model_in_cooldown("gemini-flash-lite-latest"))
        self.assertIn("gemini-flash-lite-latest", get_model_cooldowns())

        # Put all models in cooldown
        for m in MODEL_FALLBACK_CHAIN:
            _set_model_cooldown(m, GeminiErrorKind.RATE_LIMITED)
            self.assertTrue(_is_model_in_cooldown(m))

        # Resetting clears all cooldowns
        reset_model_cooldowns()
        for m in MODEL_FALLBACK_CHAIN:
            self.assertFalse(_is_model_in_cooldown(m))

    def test_endpoint_language_and_persona_mocked(self):
        """Verify chat_with_cybersaathi produces language-consistent, feminine output."""
        # English greeting with Hindi UI setting
        req = ChatRequest(message="hello cyber Sathi how are you", language="हिंदी")
        with patch("routes.chatbot.genai.Client") as mock_client:
            mock_client.return_value.models.generate_content.return_value.text = (
                "Hello! I am CyberSaathi, your digital safety assistant. I am doing well! How can I assist you with your digital security today?"
            )
            resp = chat_with_cybersaathi(req)
            self.assertIn("Hello! I am CyberSaathi", resp.response)
            self.assertNotIn("नमस्ते", resp.response)


if __name__ == "__main__":
    unittest.main()
