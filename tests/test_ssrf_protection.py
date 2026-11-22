import os
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
os.chdir(str(BACKEND_DIR))

from routes.utils import is_safe_public_url, download_media_from_url
from routes.detectors import scan_link, LinkScanRequest


class TestSSRFProtection(unittest.TestCase):
    def test_is_safe_public_url_blocks_internal_and_loopback(self):
        blocked_targets = [
            "http://127.0.0.1:8000",
            "http://localhost:3000",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/admin",
            "http://192.168.1.1/router",
            "http://172.16.0.1/status",
            "http://0.0.0.0:8080",
            "http://[::1]/",
            "ftp://example.com/file",
            "file:///etc/passwd",
            "http://metadata.google.internal/computeMetadata/v1/",
            # Alternate IP representations
            "http://2130706433/",        # Decimal integer IP for 127.0.0.1
            "http://0x7f000001/",        # Hex integer IP for 127.0.0.1
            "http://0177.0.0.1/",        # Dotted octal for 127.0.0.1
            "http://2852039166/",        # Decimal integer for 169.254.169.254
            # Restricted internal service ports
            "http://example.com:22/",     # SSH port
            "http://example.com:6379/",   # Redis port
            "http://example.com:27017/",  # MongoDB port
        ]
        for target in blocked_targets:
            is_safe, err = is_safe_public_url(target)
            self.assertFalse(
                is_safe,
                f"Target should have been blocked by SSRF filter: {target}",
            )
            self.assertIsNotNone(err)

    def test_is_safe_public_url_allows_public_hosts(self):
        is_safe, err = is_safe_public_url("https://google.com")
        self.assertTrue(is_safe, f"Public domain should be allowed: {err}")
        self.assertIsNone(err)

    def test_scan_link_ssrf_blocking_does_not_falsely_accuse_as_malicious(self):
        resp = scan_link(LinkScanRequest(url="http://127.0.0.1:8000/internal-admin"))
        self.assertEqual(resp.get("overall_status"), "Blocked")
        self.assertEqual(resp.get("verdict"), "BLOCKED")
        self.assertEqual(resp.get("malicious_count"), 0)
        self.assertTrue(resp.get("invalid_domain"))
        self.assertTrue(
            any("SSRF" in t or "restricted" in t.lower() or "internal" in t.lower() for t in resp.get("threat_indicators", [])),
            f"Expected SSRF threat warning in: {resp.get('threat_indicators')}",
        )

    def test_download_media_blocks_ssrf(self):
        file_path, err = download_media_from_url("http://169.254.169.254/latest/meta-data/")
        self.assertIsNone(file_path)
        self.assertIsNotNone(err)
        self.assertTrue("SSRF" in err or "forbidden" in err.lower() or "restricted" in err.lower())


if __name__ == "__main__":
    unittest.main()
