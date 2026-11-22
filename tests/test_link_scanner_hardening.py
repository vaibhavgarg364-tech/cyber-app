import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
os.chdir(str(BACKEND_DIR))

from routes.utils import is_restricted_ip, is_safe_public_url
from routes.website_scanner import (
    ResearchScanner,
    run_heuristic_analysis,
    normalize_url,
    is_trusted_host,
)
from routes.detectors import scan_link, LinkScanRequest


class TestLinkScannerHardening(unittest.TestCase):

    def test_fixture_d_nat64_and_restricted_ip(self):
        """Fixture D: NAT64 translation address with public IPv4 must be allowed;
        NAT64 address embedding loopback/private/metadata IPv4 must be blocked."""
        # Public IP 103.224.182.242 embedded in 64:ff9b::/96 -> 64:ff9b::67e0:b6f2
        is_restr, _ = is_restricted_ip("64:ff9b::67e0:b6f2")
        self.assertFalse(
            is_restr,
            "NAT64 address with public IPv4 (103.224.182.242) should not be restricted",
        )
        # SSRF Evasion: loopback 127.0.0.1 embedded in NAT64
        is_restr, _ = is_restricted_ip("64:ff9b::7f00:1")
        self.assertTrue(
            is_restr,
            "NAT64 address embedding 127.0.0.1 must be restricted",
        )
        # SSRF Evasion: AWS metadata 169.254.169.254 embedded in NAT64
        is_restr, _ = is_restricted_ip("64:ff9b::a9fe:a9fe")
        self.assertTrue(
            is_restr,
            "NAT64 address embedding 169.254.169.254 must be restricted",
        )
        # Standard IPv4 loopback
        is_restr, _ = is_restricted_ip("127.0.0.1")
        self.assertTrue(is_restr)
        # Standard public IPv4
        is_restr, _ = is_restricted_ip("8.8.8.8")
        self.assertFalse(is_restr)

    def test_fixture_e_trusted_domain_truth_in_security(self):
        """Fixture E: wikipedia.org must be Trusted without fabricated engine counts."""
        self.assertTrue(is_trusted_host("wikipedia.org"))
        scanner = ResearchScanner("https://wikipedia.org")
        res = scanner.execute_scan()

        self.assertEqual(res["overall_status"], "Trusted")
        self.assertEqual(res["verdict"], "safe")
        self.assertEqual(res["total_engines"], 0, "External engines must be 0 when not queried")
        self.assertEqual(res["safe_count"], 0, "safe_count must be 0 when external engines not queried")
        self.assertFalse(res["api_status"]["virustotal"]["used"])
        self.assertEqual(res["api_status"]["virustotal"]["status"], "NOT_QUERIED")
        self.assertFalse(res["api_status"]["google_safe_browsing"]["used"])
        self.assertEqual(res["api_status"]["google_safe_browsing"]["status"], "NOT_QUERIED")

    def test_fixture_a_rfc_reserved_executable_unreachable(self):
        """Fixture A: malicious-site.example/download.exe has .example reserved TLD and .exe target.
        Must not receive 'Trusted' or 'Safe' verdict; must be flagged Suspicious/Dangerous."""
        scanner = ResearchScanner("http://malicious-site.example/download.exe")
        res = scanner.execute_scan()

        self.assertNotEqual(res["overall_status"], "Trusted")
        self.assertNotEqual(res["overall_status"], "Low Risk")
        self.assertIn(res["overall_status"], ["Suspicious", "Dangerous"])
        self.assertIn(res["verdict"], ["suspicious", "dangerous"])
        self.assertTrue(res["invalid_domain"])
        self.assertIn("Unreachable", res["connection_status"])
        self.assertLessEqual(res["confidence_percent"], 40)

    def test_fixture_b_embedded_url_and_executable_payload(self):
        """Fixture B: URL with secondary embedded scheme and .exe in path must be flagged."""
        canonical_url, canonical_hostname = normalize_url(
            "http://malicious-site.example/download.exehttp://9779.info/20140228/s.exe"
        )
        h = run_heuristic_analysis(canonical_url, canonical_hostname)

        self.assertGreaterEqual(h["risk_score"], 50)
        self.assertIn(h["overall_status"], ["Suspicious", "Dangerous"])
        threats_str = " ".join(h["threat_indicators"])
        self.assertTrue(
            "embedded" in threats_str.lower() or "scheme" in threats_str.lower() or "secondary" in threats_str.lower(),
            f"Expected secondary URL scheme indicator, got: {threats_str}",
        )
        self.assertTrue(
            "executable" in threats_str.lower() or "payload" in threats_str.lower() or ".exe" in threats_str.lower(),
            f"Expected executable payload indicator, got: {threats_str}",
        )

    def test_fixture_c_brand_impersonation_detection(self):
        """Fixture C: paypa1-login.example.com must detect brand impersonation of PayPal."""
        canonical_url, canonical_hostname = normalize_url("http://paypa1-login.example.com")
        h = run_heuristic_analysis(canonical_url, canonical_hostname)

        self.assertFalse(h["is_trusted"])
        self.assertNotEqual(h["overall_status"], "Trusted")
        self.assertIn(h["overall_status"], ["Suspicious", "Dangerous"])
        self.assertIsNotNone(h.get("brand_impersonation"))
        self.assertEqual(h["brand_impersonation"]["brand"], "paypal")

    def test_unreachable_unknown_domain_evidence_semantics(self):
        """A non-existent domain without threat patterns must be 'Unknown' / 'uncertain', NOT 'SAFE'."""
        scanner = ResearchScanner("http://non-existent-random-domain-778899.org")
        res = scanner.execute_scan()

        self.assertNotEqual(res["overall_status"], "Trusted")
        self.assertNotEqual(res["overall_status"], "Low Risk")
        self.assertEqual(res["overall_status"], "Unknown")
        self.assertEqual(res["verdict"], "uncertain")
        self.assertLessEqual(res["confidence_percent"], 25)
        self.assertIn("Unreachable", res["connection_status"])

    def test_provider_status_tracking(self):
        """Provider status must report honest statuses without fabricated engine counts."""
        scanner = ResearchScanner("https://example.com")
        # Mock virustotal response as rate-limited 429
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 429
            mock_get.return_value = mock_resp
            stats, status = scanner._vt_lookup()
            self.assertEqual(status, "RATE_LIMITED")
            self.assertEqual(sum(stats.values()), 0)


if __name__ == "__main__":
    unittest.main()
