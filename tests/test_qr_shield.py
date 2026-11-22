import io
import os
import sys
import unittest
from pathlib import Path

import cv2
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
os.chdir(str(BACKEND_DIR))

from routes.qr_engine import (
    decode_qr_image_bytes,
    classify_payload_type,
    analyze_upi_payload,
    analyze_wifi_payload,
    analyze_contact_payload,
    analyze_text_payload,
    evaluate_qr_payload,
)


class TestQRShieldEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        encoder = cv2.QRCodeEncoder.create()
        img = encoder.encode("https://google.com/test-qr")
        img_scaled = cv2.resize(img, (290, 290), interpolation=cv2.INTER_NEAREST)
        _, buf = cv2.imencode(".png", img_scaled)
        cls.valid_qr_bytes = buf.tobytes()

    def test_decode_valid_qr_image(self):
        text, err = decode_qr_image_bytes(self.valid_qr_bytes)
        self.assertIsNone(err)
        self.assertEqual(text, "https://google.com/test-qr")

    def test_decode_raw_unpadded_matrix(self):
        """Test decoding raw 29x29 matrix directly from QRCodeEncoder without pre-padding."""
        encoder = cv2.QRCodeEncoder.create()
        raw_mat = encoder.encode("https://veyron.cybercell/secure-target")
        _, buf = cv2.imencode(".png", raw_mat)
        text, err = decode_qr_image_bytes(buf.tobytes())
        self.assertIsNone(err)
        self.assertEqual(text, "https://veyron.cybercell/secure-target")

    def test_decode_rotated_qr_code(self):
        """Test decoding QR code rotated 90 degrees."""
        encoder = cv2.QRCodeEncoder.create()
        raw_mat = encoder.encode("upi://pay?pa=shop@upi&pn=Retail&am=50&cu=INR")
        # Add slight border and rotate
        padded = cv2.copyMakeBorder(raw_mat, 10, 10, 10, 10, cv2.BORDER_CONSTANT, value=255)
        scaled = cv2.resize(padded, (padded.shape[1] * 4, padded.shape[0] * 4), interpolation=cv2.INTER_NEAREST)
        rotated = cv2.rotate(scaled, cv2.ROTATE_90_CLOCKWISE)
        _, buf = cv2.imencode(".png", rotated)
        text, err = decode_qr_image_bytes(buf.tobytes())
        self.assertIsNone(err)
        self.assertEqual(text, "upi://pay?pa=shop@upi&pn=Retail&am=50&cu=INR")

    def test_decode_dark_mode_inverted_qr_code(self):
        """Test decoding inverted (white-on-black) QR code."""
        encoder = cv2.QRCodeEncoder.create()
        raw_mat = encoder.encode("WIFI:T:WPA;S:SecureOffice;P:OfficePass2026;;")
        padded = cv2.copyMakeBorder(raw_mat, 8, 8, 8, 8, cv2.BORDER_CONSTANT, value=255)
        scaled = cv2.resize(padded, (padded.shape[1] * 4, padded.shape[0] * 4), interpolation=cv2.INTER_NEAREST)
        inverted = cv2.bitwise_not(scaled)
        _, buf = cv2.imencode(".png", inverted)
        text, err = decode_qr_image_bytes(buf.tobytes())
        self.assertIsNone(err)
        self.assertEqual(text, "WIFI:T:WPA;S:SecureOffice;P:OfficePass2026;;")

    def test_decode_blank_image_returns_error(self):
        blank = np.zeros((200, 200, 3), dtype=np.uint8)
        _, buf = cv2.imencode(".png", blank)
        text, err = decode_qr_image_bytes(buf.tobytes())
        self.assertIsNone(text)
        self.assertIsNotNone(err)
        self.assertIn("No QR code", err)

    def test_classify_payload_types(self):
        self.assertEqual(classify_payload_type("https://secure-bank.com"), "url")
        self.assertEqual(classify_payload_type("http://example.org/test"), "url")
        self.assertEqual(classify_payload_type("upi://pay?pa=merchant@okhdfcbank"), "upi")
        self.assertEqual(classify_payload_type("WIFI:T:WPA;S:MyNet;P:pass;;"), "wifi")
        self.assertEqual(classify_payload_type("BEGIN:VCARD\nFN:Officer\nEND:VCARD"), "contact")
        self.assertEqual(classify_payload_type("MECARD:N:Officer;TEL:9876543210;;"), "contact")
        self.assertEqual(classify_payload_type("Hello Veyron Security Team"), "text")

    def test_upi_scam_detection(self):
        scam_upi = "upi://pay?pa=electricity-bill-refund@okhdfcbank&pn=Urgent%20Refund%20Officer&am=45000&cu=INR"
        res = analyze_upi_payload(scam_upi)
        self.assertEqual(res["payload_type"], "upi")
        self.assertEqual(res["verdict"], "HIGH RISK")
        self.assertGreaterEqual(res["risk_score"], 70)
        self.assertEqual(res["parsed_data"]["amount"], 45000.0)
        self.assertEqual(res["parsed_data"]["currency"], "INR")
        # Universal Indian safety rule
        self.assertTrue(any("only SENDS money" in rec for rec in res["recommendations"]))
        self.assertTrue(any("refund" in ind.lower() for ind in res["threat_indicators"]))

    def test_upi_no_known_threat(self):
        safe_upi = "upi://pay?pa=kirana.store@paytm&pn=Shri%20Ganesh%20Store&am=120.00&cu=INR"
        res = analyze_upi_payload(safe_upi)
        self.assertEqual(res["payload_type"], "upi")
        self.assertEqual(res["verdict"], "NO KNOWN THREAT DETECTED")
        self.assertLess(res["risk_score"], 40)
        self.assertEqual(res["parsed_data"]["amount"], 120.0)

    def test_wifi_unencrypted_nopass_risk(self):
        open_wifi = "WIFI:T:nopass;S:Airport_Free_WiFi;P:;;;H:false"
        res = analyze_wifi_payload(open_wifi)
        self.assertEqual(res["payload_type"], "wifi")
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertGreaterEqual(res["risk_score"], 50)
        self.assertFalse(res["parsed_data"]["password_present"])
        self.assertTrue(any("Unencrypted" in ind or "Configuration Risk" in ind for ind in res["threat_indicators"]))

    def test_wifi_wpa_secure(self):
        sec_wifi = "WIFI:T:WPA;S:HomeNetwork_5G;P:SecurePass987;;;H:false"
        res = analyze_wifi_payload(sec_wifi)
        self.assertEqual(res["payload_type"], "wifi")
        self.assertEqual(res["verdict"], "NO KNOWN THREAT DETECTED")
        self.assertTrue(res["parsed_data"]["password_present"])

    def test_contact_vcard_parsing(self):
        vcard = "BEGIN:VCARD\nVERSION:3.0\nFN:CBI Cyber Police\nORG:Central Bureau\nTEL:+919876543210\nEND:VCARD"
        res = analyze_contact_payload(vcard)
        self.assertEqual(res["payload_type"], "contact")
        self.assertEqual(res["parsed_data"]["name"], "CBI Cyber Police")
        self.assertIn("+919876543210", res["parsed_data"]["phone_numbers"])
        self.assertEqual(res["verdict"], "SUSPICIOUS")

    def test_text_scam_keywords(self):
        scam_text = "Urgent: Your electricity will be disconnected tonight. Send OTP immediately to avoid account block."
        res = analyze_text_payload(scam_text)
        self.assertEqual(res["payload_type"], "text")
        self.assertEqual(res["verdict"], "HIGH RISK")
        self.assertGreaterEqual(res["risk_score"], 40)

    def test_evaluate_qr_payload_url_ssrf_protection(self):
        res = evaluate_qr_payload("http://127.0.0.1:8000/internal-admin")
        self.assertEqual(res["payload_type"], "url")
        self.assertEqual(res["verdict"], "HIGH RISK")
        self.assertTrue(any("SSRF" in ind or "restricted" in ind.lower() for ind in res["threat_indicators"]))

    def test_evaluate_dangerous_uri_schemes(self):
        res = evaluate_qr_payload("javascript:alert(document.cookie)")
        self.assertEqual(res["payload_type"], "url")
        self.assertEqual(res["verdict"], "HIGH RISK")
        self.assertEqual(res["risk_score"], 100)
        self.assertTrue(any("dangerous URI scheme" in ind for ind in res["threat_indicators"]))

    def test_evaluate_oversized_payload(self):
        oversized = "A" * 10000
        res = evaluate_qr_payload(oversized)
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertTrue(any("exceeds standard QR capacity" in ind for ind in res["threat_indicators"]))


if __name__ == "__main__":
    unittest.main()
