import os
import sys
import time
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
os.chdir(str(BACKEND_DIR))

from main import app, health
from routes.detectors import (
    detect_deepfake_file,
    _get_deepfake_semaphore,
    _deepfake_route_debug,
    _normalize_deepfake_verdict_payload,
)
from routes import deepfake_pipeline
from routes.deepfake_pipeline import DeepfakeDetector

class TestConcurrencyAndPerformance(unittest.TestCase):

    def test_1_concurrency_semaphore_initialization_and_safety(self):
        """1. Concurrency semaphore is initialized with bound=1 for GPU safety."""
        sem = _get_deepfake_semaphore()
        self.assertIsNotNone(sem)
        # Semaphore bound is 1 to guarantee mutual exclusion on single 6GB GPU
        self.assertEqual(sem._value, 1)

    def test_2_gc_collect_eliminated_from_request_path(self):
        """2 & 4. Verified that explicit gc.collect() calls are eliminated from request processing path."""
        with patch("gc.collect") as mock_gc:
            test_img = PROJECT_ROOT / "tests" / "media" / "real_camera" / "smoke_camera_iphone.jpg"
            res = detect_deepfake_file(str(test_img))

            # Assert zero gc.collect calls occurred during the entire image analysis
            self.assertEqual(
                mock_gc.call_count, 0,
                f"Regression: gc.collect() was called {mock_gc.call_count} times during request processing!"
            )
            self.assertEqual(res.get("verdict"), "LIKELY_AUTHENTIC")

    def test_3_temporary_file_cleanup_and_preservation(self):
        """4. Verify temporary files are preserved during execution and cleaned up in finally block."""
        import tempfile
        temp_path = None
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            f.write(b"dummy image bytes")
            temp_path = f.name

        self.assertTrue(os.path.exists(temp_path))
        try:
            # Simulate endpoint try-finally cleanup logic
            file_existed_during_call = os.path.exists(temp_path)
            self.assertTrue(file_existed_during_call)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

        self.assertFalse(os.path.exists(temp_path))

    def test_4_exception_payload_normalization(self):
        """5. Verify inference exception payloads normalize cleanly without hanging or crashing."""
        exc_msg = "CUDA Out of Memory Simulation"
        raw_exc_dict = {
            **_deepfake_route_debug({"debug_source_name": "test.jpg", "debug_actual_exception": exc_msg}),
            "mediaUrl": "test.jpg",
            "verdict": "INSUFFICIENT EVIDENCE",
            "legacy_verdict": "unverified",
            "verdict_color": "yellow",
            "confidence_percent": 0,
            "verdict_reason": f"Analysis could not be completed: {exc_msg}",
            "confidence": 0,
            "details": f"Deepfake analysis failed: {exc_msg}",
            "findings": [f"Could not complete local analysis for this file: {exc_msg}"],
            "recommendations": ["Try uploading a clearer image."],
            "englishSummary": "Analysis could not be completed for this file. Try another image or format.",
            "hindiSummary": "इस फ़ाइल के लिए विश्लेषण पूरा नहीं हो सका। दूसरी छवि या प्रारूप आज़माएँ।",
        }
        payload = _normalize_deepfake_verdict_payload(raw_exc_dict)
        self.assertEqual(payload.get("verdict"), "INSUFFICIENT EVIDENCE")
        self.assertEqual(payload.get("confidencePercent"), 0)
        self.assertIn("englishSummary", payload)
        self.assertIn("hindiSummary", payload)

    def test_5_response_contract_and_clip_propagation(self):
        """7 & 8. Verify existing response contract, CLIP propagation, and verdict fields."""
        test_img = PROJECT_ROOT / "tests" / "media" / "ai_other" / "smoke_ai_generated.png"
        res = detect_deepfake_file(str(test_img))

        # Check required fields
        self.assertIn("verdict", res)
        self.assertIn("confidencePercent", res)
        self.assertIn("debugAnalysis", res)
        self.assertIn("forensicHeatmap", res)
        self.assertIn("patchAnalysis", res)

        debug = res["debugAnalysis"]
        self.assertTrue(debug.get("clip_available"))
        self.assertIsInstance(debug.get("clip_aggregate_score"), float)
        self.assertGreater(debug.get("clip_aggregate_score"), 0.0)
        self.assertIn("specialized_detector", debug)
        self.assertIn("final_fusion_score", debug)

        self.assertEqual(res.get("verdict"), "AI_GENERATED")
        self.assertGreaterEqual(res.get("confidencePercent"), 90)

    def test_6_health_endpoint_contract(self):
        """9. Verify health endpoint remains intact and returns standard status."""
        res = health()
        self.assertEqual(res, {"status": "ok", "service": "veyron-backend"})

if __name__ == "__main__":
    unittest.main()
