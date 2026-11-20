import os
import sys
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from routes.deepfake_pipeline import (
    AIEnsembleClassifier,
    EnsembleResult,
    ModelResult,
    PatchForensicResult,
    fuse_signals,
    SignalResult,
    _get_classifier,
)


class TestClipPropagation(unittest.TestCase):
    def setUp(self):
        self.dummy_signals = [
            SignalResult(
                key="sensor_noise",
                score=0.45,
                detail="Synthetic sensor noise check",
                category="sensor_noise",
                status="active",
                reliability="medium",
                human_readable="Camera sensor noise pattern consistency.",
                confidence_interval=(0.35, 0.55),
                confidence=0.65,
            )
        ]
        self.dummy_patch = PatchForensicResult(
            available=False,
            mean_score=0.0,
            peak_score=0.0,
            suspicious_density=0.0,
            clustering_score=0.0,
            patches=[],
            heatmap_path=None,
        )
        self.dummy_ctype = {"type": "standard_image", "reasons": []}

    def test_known_nonzero_clip_result_propagates(self):
        """A known nonzero CLIP result must reach the final debugAnalysis object."""
        mock_clip = {
            "available": True,
            "status": "active",
            "real_prompt_scores": {"genuine photo": 0.12},
            "ai_prompt_scores": {"synthetic render": 0.7433},
            "aggregate_score": 0.7433,
            "confidence": 0.4866,
            "detail": "CLIP raw AI aggregate: 0.7433",
            "inference_time": 0.15,
        }
        mock_spec = ModelResult(
            available=True,
            model_name="umm-maybe/AI-image-detector",
            ai_probability=0.4298,
            confidence=0.1404,
            detail="Specialized AI score: 0.4298",
            inference_time=0.05,
        )
        mock_ens_results = [
            mock_spec,
            ModelResult(
                available=True,
                model_name="openai/clip-vit-base-patch32",
                ai_probability=0.7433,
                confidence=0.4866,
                detail="CLIP score",
                inference_time=0.15,
            ),
        ]
        ens_res = EnsembleResult(
            available=True,
            results=mock_ens_results,
            ensemble_score=0.45,
            ensemble_confidence=0.25,
            agreement_score=0.68,
            disagreement=False,
            inference_time_total=0.20,
            weights={"umm-maybe/AI-image-detector": 0.95, "openai/clip-vit-base-patch32": 0.05},
            detail="Summary",
            clip_result=mock_clip,
            specialized_result=mock_spec,
        )

        res = fuse_signals(
            self.dummy_signals,
            ens_res,
            self.dummy_patch,
            self.dummy_ctype,
            prov_data={},
            file_path="test.jpg",
        )

        debug = res.get("debugAnalysis", {})
        self.assertTrue(debug.get("clip_available"))
        self.assertEqual(debug.get("clip_status"), "active")
        self.assertEqual(debug.get("clip_aggregate_score"), 0.7433)
        self.assertEqual(debug.get("clip_confidence"), 0.4866)
        self.assertEqual(debug.get("clip_raw_ai_scores"), {"synthetic render": 0.7433})
        self.assertEqual(debug.get("clip_raw_real_scores"), {"genuine photo": 0.12})

    def test_no_second_classifier_constructed_during_fusion(self):
        """fuse_signals must not call _get_classifier() to retrieve inference state."""
        mock_clip = {
            "available": True,
            "status": "active",
            "real_prompt_scores": {},
            "ai_prompt_scores": {},
            "aggregate_score": 0.65,
            "confidence": 0.30,
            "detail": "detail",
            "inference_time": 0.1,
        }
        ens_res = EnsembleResult(
            available=True,
            results=[],
            ensemble_score=0.5,
            ensemble_confidence=0.5,
            agreement_score=1.0,
            disagreement=False,
            inference_time_total=0.1,
            weights={},
            detail="Summary",
            clip_result=mock_clip,
        )

        # Patch _get_classifier to raise an assertion error if called
        with patch("routes.deepfake_pipeline._get_classifier") as mock_get:
            mock_get.side_effect = RuntimeError("Second classifier lookup must NOT occur during fusion!")
            # This must succeed without calling _get_classifier
            res = fuse_signals(
                self.dummy_signals,
                ens_res,
                self.dummy_patch,
                self.dummy_ctype,
                prov_data={},
                file_path="test.jpg",
            )
            debug = res.get("debugAnalysis", {})
            self.assertEqual(debug.get("clip_aggregate_score"), 0.65)
            mock_get.assert_not_called()

    def test_clip_unavailable_handled_honestly(self):
        """When CLIP fails or is unavailable, debugAnalysis reflects None, not 0.0 masquerading as success."""
        mock_clip = {
            "available": False,
            "status": "MODEL_UNAVAILABLE",
            "real_prompt_scores": {},
            "ai_prompt_scores": {},
            "aggregate_score": 0.0,
            "confidence": 0.0,
            "detail": "CLIP model unavailable",
            "inference_time": 0.0,
        }
        mock_spec = ModelResult(
            available=True,
            model_name="umm-maybe/AI-image-detector",
            ai_probability=0.85,
            confidence=0.70,
            detail="Specialized detector",
            inference_time=0.03,
        )
        ens_res = EnsembleResult(
            available=True,
            results=[
                mock_spec,
                ModelResult(
                    available=False,
                    model_name="openai/clip-vit-base-patch32",
                    ai_probability=0.0,
                    confidence=0.0,
                    detail="MODEL_UNAVAILABLE",
                    inference_time=0.0,
                ),
            ],
            ensemble_score=0.85,
            ensemble_confidence=0.70,
            agreement_score=1.0,
            disagreement=False,
            inference_time_total=0.03,
            weights={"umm-maybe/AI-image-detector": 1.0},
            detail="Summary",
            clip_result=mock_clip,
            specialized_result=mock_spec,
        )

        res = fuse_signals(
            self.dummy_signals,
            ens_res,
            self.dummy_patch,
            self.dummy_ctype,
            prov_data={},
            file_path="test.jpg",
        )

        debug = res.get("debugAnalysis", {})
        self.assertFalse(debug.get("clip_available"))
        self.assertEqual(debug.get("clip_status"), "MODEL_UNAVAILABLE")
        self.assertIsNone(debug.get("clip_aggregate_score"))
        self.assertIsNone(debug.get("clip_confidence"))

        # Primary detector still operates and triggers correct verdict
        spec = debug.get("specialized_detector", {})
        self.assertTrue(spec.get("available"))
        self.assertEqual(spec.get("score"), 0.85)
        self.assertIn("AI", res.get("verdict", ""))

    def test_concurrent_requests_cannot_cross_pollinate_clip_scores(self):
        """Separate request executions maintain isolated per-request CLIP state."""
        import copy

        clip_req1 = {
            "available": True,
            "status": "active",
            "aggregate_score": 0.8888,
            "confidence": 0.7777,
            "real_prompt_scores": {},
            "ai_prompt_scores": {},
            "detail": "req1",
            "inference_time": 0.1,
        }
        clip_req2 = {
            "available": True,
            "status": "active",
            "aggregate_score": 0.2222,
            "confidence": 0.5555,
            "real_prompt_scores": {},
            "ai_prompt_scores": {},
            "detail": "req2",
            "inference_time": 0.1,
        }

        ens1 = EnsembleResult(
            available=True,
            results=[ModelResult(True, "openai/clip-vit-base-patch32", 0.8888, 0.7777, "", 0.1)],
            ensemble_score=0.8888,
            ensemble_confidence=0.7777,
            agreement_score=1.0,
            disagreement=False,
            inference_time_total=0.1,
            weights={},
            detail="",
            clip_result=clip_req1,
        )
        ens2 = EnsembleResult(
            available=True,
            results=[ModelResult(True, "openai/clip-vit-base-patch32", 0.2222, 0.5555, "", 0.1)],
            ensemble_score=0.2222,
            ensemble_confidence=0.5555,
            agreement_score=1.0,
            disagreement=False,
            inference_time_total=0.1,
            weights={},
            detail="",
            clip_result=clip_req2,
        )

        res1 = fuse_signals(
            self.dummy_signals, ens1, self.dummy_patch, self.dummy_ctype, prov_data={}, file_path="img1.jpg"
        )
        res2 = fuse_signals(
            self.dummy_signals, ens2, self.dummy_patch, self.dummy_ctype, prov_data={}, file_path="img2.jpg"
        )

        self.assertEqual(res1["debugAnalysis"]["clip_aggregate_score"], 0.8888)
        self.assertEqual(res2["debugAnalysis"]["clip_aggregate_score"], 0.2222)

    def test_real_clip_inference_with_cached_model(self):
        """Smoke test verifying real CLIP inference using the locally cached model weights."""
        from PIL import Image

        # Generate a simple 224x224 RGB test image
        arr = np.full((224, 224, 3), 128, dtype=np.uint8)
        bgr = arr.copy()

        classifier = AIEnsembleClassifier()
        ens_res = classifier.score_image(bgr)

        # Check EnsembleResult has clip_result attached
        self.assertIsNotNone(ens_res.clip_result)
        self.assertTrue(ens_res.clip_result.get("available"))
        self.assertGreater(ens_res.clip_result.get("aggregate_score", 0), 0)

        # Check fusion incorporates real CLIP scores
        fused = fuse_signals(
            self.dummy_signals, ens_res, self.dummy_patch, self.dummy_ctype, prov_data={}, file_path="smoke.jpg"
        )
        debug = fused.get("debugAnalysis", {})
        self.assertTrue(debug.get("clip_available"))
        self.assertEqual(debug.get("clip_status"), "active")
        self.assertIsInstance(debug.get("clip_aggregate_score"), float)
        self.assertGreater(debug.get("clip_aggregate_score"), 0.0)
        self.assertIsInstance(debug.get("clip_confidence"), float)
        self.assertTrue(len(debug.get("clip_raw_real_scores", {})) > 0)
        self.assertTrue(len(debug.get("clip_raw_ai_scores", {})) > 0)


if __name__ == "__main__":
    unittest.main()
