import os
import sys
import unittest
import tempfile
from pathlib import Path
from PIL import Image

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
os.chdir(str(BACKEND_DIR))

from routes.detectors import check_app, AppCheckRequest, detect_deepfake_file


class TestEndpointsSmoke(unittest.TestCase):
    def test_check_app_endpoints(self):
        """Smoke test for check_app covering mAadhaar, Aadhaar, pasted URL, and WhatsApp."""
        # 1. mAadhaar
        resp_m = check_app(AppCheckRequest(appName="mAadhaar"))
        self.assertEqual(resp_m.get("verdict"), "official")
        self.assertEqual(resp_m.get("appName"), "mAadhaar")
        self.assertEqual(resp_m.get("officialPackage"), "in.gov.uidai.mAadhaarPlus")
        self.assertEqual(
            resp_m.get("playStoreLink"),
            "https://play.google.com/store/apps/details?id=in.gov.uidai.mAadhaarPlus",
        )

        # 2. Aadhaar
        resp_a = check_app(AppCheckRequest(appName="Aadhaar"))
        self.assertEqual(resp_a.get("verdict"), "official")
        self.assertEqual(resp_a.get("appName"), "Aadhaar")
        self.assertEqual(resp_a.get("officialPackage"), "in.gov.uidai.pehchaan")
        self.assertEqual(
            resp_a.get("playStoreLink"),
            "https://play.google.com/store/apps/details?id=in.gov.uidai.pehchaan",
        )

        # 3. Pasted Play Store URL
        pasted_url = "https://play.google.com/store/apps/details?id=in.gov.uidai.mAadhaarPlus"
        resp_u = check_app(AppCheckRequest(appName=pasted_url))
        self.assertEqual(resp_u.get("verdict"), "official")
        self.assertEqual(resp_u.get("officialPackage"), "in.gov.uidai.mAadhaarPlus")
        self.assertEqual(
            resp_u.get("playStoreLink"),
            "https://play.google.com/store/apps/details?id=in.gov.uidai.mAadhaarPlus",
        )

        # 4. WhatsApp
        resp_wa = check_app(AppCheckRequest(appName="WhatsApp"))
        self.assertEqual(resp_wa.get("officialAlternatives"), [])
        if resp_wa.get("playStoreLink"):
            self.assertNotIn("in.gov.uidai", resp_wa["playStoreLink"])
            self.assertNotIn("com.facebook.id", resp_wa["playStoreLink"])

    def test_detect_deepfake_endpoint_real_clip_scores(self):
        """Smoke test for deepfake detection verifying real CLIP scores in debugAnalysis."""
        img = Image.new("RGB", (250, 250), color=(140, 150, 160))
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            img.save(f.name, format="JPEG")
            temp_path = f.name

        try:
            data = detect_deepfake_file(temp_path)
            self.assertIn("debugAnalysis", data)
            debug = data["debugAnalysis"]

            # Assert CLIP executed and debug payload is populated
            self.assertTrue(debug.get("clip_available"))
            self.assertEqual(debug.get("clip_status"), "active")
            self.assertIsInstance(debug.get("clip_aggregate_score"), float)
            self.assertGreater(debug.get("clip_aggregate_score"), 0.0)
            self.assertIsInstance(debug.get("clip_confidence"), float)
            self.assertTrue(len(debug.get("clip_raw_real_scores", {})) > 0)
            self.assertTrue(len(debug.get("clip_raw_ai_scores", {})) > 0)
            print("\n[SMOKE TEST RESULT] detect_deepfake_file:")
            print(f"  CLIP available: {debug.get('clip_available')}")
            print(f"  CLIP status: {debug.get('clip_status')}")
            print(f"  CLIP aggregate score: {debug.get('clip_aggregate_score')}")
            print(f"  CLIP confidence: {debug.get('clip_confidence')}")
            print(f"  CLIP raw AI scores: {debug.get('clip_raw_ai_scores')}")
            print(f"  Verdict: {data.get('verdict')}")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


if __name__ == "__main__":
    unittest.main()
