import unittest
import sys
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from routes.deepfake_pipeline import (
    ModelResult,
    EnsembleResult,
    PatchForensicResult,
    SignalResult,
    fuse_signals,
    _calibrate_ml_probability,
    _dynamic_signal_weight,
    AIEnsembleClassifier,
)


class TestDeepfakeDecisionFixes(unittest.TestCase):
    def setUp(self):
        self.dummy_signals = [
            SignalResult(
                key="sensor_noise",
                score=0.50,
                detail="Synthetic sensor noise check",
                category="sensor_noise",
                status="active",
                reliability="medium",
                human_readable="Camera sensor noise pattern consistency.",
                confidence_interval=(0.40, 0.60),
                confidence=0.50,
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

    def test_single_model_veto_removed_when_clip_conflicts(self):
        """Case A: When specialized model gives low score (0.239) but CLIP gives high score (0.7652),

        the pipeline MUST NOT veto the image to LIKELY_AUTHENTIC.
        """
        mock_spec = ModelResult(
            available=True,
            model_name="umm-maybe/AI-image-detector",
            ai_probability=0.239,
            confidence=0.522,
            detail="Specialized score",
            inference_time=0.05,
        )
        mock_clip = {
            "available": True,
            "status": "active",
            "real_prompt_scores": {"real camera": 0.15},
            "ai_prompt_scores": {"ai generated": 0.7652},
            "aggregate_score": 0.7652,
            "confidence": 0.5304,
            "detail": "CLIP score",
            "inference_time": 0.1,
        }
        ens_res = EnsembleResult(
            available=True,
            results=[
                mock_spec,
                ModelResult(True, "openai/clip-vit-base-patch32", 0.7652, 0.53, "CLIP", 0.1),
            ],
            ensemble_score=0.80 * 0.239 + 0.20 * 0.7652,
            ensemble_confidence=0.50,
            agreement_score=0.47,
            disagreement=True,
            inference_time_total=0.15,
            weights={"umm-maybe/AI-image-detector": 0.80, "openai/clip-vit-base-patch32": 0.20},
            detail="Ensemble summary",
            clip_result=mock_clip,
            specialized_result=mock_spec,
        )

        fused = fuse_signals(
            self.dummy_signals,
            ens_res,
            self.dummy_patch,
            self.dummy_ctype,
            prov_data={},
            file_path="synthetic_portrait.jpg",
        )

        verdict = fused["verdict"]
        level = fused.get("debugAnalysis", {}).get("decision_hierarchy_level_triggered")
        # Must not be erroneously classified as authentic!
        self.assertNotEqual(verdict, "LIKELY_AUTHENTIC")
        self.assertNotEqual(level, "LEVEL_3_SPECIALIZED_DETECTOR")
        # Due to strong conflict between spec (0.239) and CLIP (0.765), should be UNCERTAIN
        self.assertEqual(verdict, "UNCERTAIN")

    def test_photorealistic_ai_corroborated_not_inconclusive(self):
        """Case B: Photorealistic AI image where spec detector is 0.58 and CLIP is 0.68

        must trigger LIKELY_AI rather than falling into the deadband UNCERTAIN.
        """
        mock_spec = ModelResult(
            available=True,
            model_name="umm-maybe/AI-image-detector",
            ai_probability=0.58,
            confidence=0.58,
            detail="Specialized score",
            inference_time=0.05,
        )
        mock_clip = {
            "available": True,
            "status": "active",
            "real_prompt_scores": {"real camera": 0.32},
            "ai_prompt_scores": {"ai generated": 0.68},
            "aggregate_score": 0.68,
            "confidence": 0.36,
            "detail": "CLIP score",
            "inference_time": 0.1,
        }
        ens_res = EnsembleResult(
            available=True,
            results=[
                mock_spec,
                ModelResult(True, "openai/clip-vit-base-patch32", 0.68, 0.36, "CLIP", 0.1),
            ],
            ensemble_score=0.80 * 0.58 + 0.20 * 0.68,
            ensemble_confidence=0.55,
            agreement_score=0.90,
            disagreement=False,
            inference_time_total=0.15,
            weights={"umm-maybe/AI-image-detector": 0.80, "openai/clip-vit-base-patch32": 0.20},
            detail="Ensemble summary",
            clip_result=mock_clip,
            specialized_result=mock_spec,
        )

        fused = fuse_signals(
            self.dummy_signals,
            ens_res,
            self.dummy_patch,
            self.dummy_ctype,
            prov_data={},
            file_path="photorealistic_midjourney.jpg",
        )

        verdict = fused["verdict"]
        level = fused.get("debugAnalysis", {}).get("decision_hierarchy_level_triggered")
        self.assertEqual(verdict, "LIKELY_AI")
        self.assertEqual(level, "LEVEL_4_FORENSIC_FUSION_AI")
        self.assertGreaterEqual(fused.get("confidence", 0.0), 0.65)

    def test_authentic_image_without_conflict_yields_likely_authentic(self):
        """Case C: Strong authentic signal where spec is 0.15 and CLIP agrees (0.20) yields LIKELY_AUTHENTIC."""
        mock_spec = ModelResult(
            available=True,
            model_name="umm-maybe/AI-image-detector",
            ai_probability=0.15,
            confidence=0.70,
            detail="Specialized score",
            inference_time=0.05,
        )
        mock_clip = {
            "available": True,
            "status": "active",
            "real_prompt_scores": {"real camera": 0.80},
            "ai_prompt_scores": {"ai generated": 0.20},
            "aggregate_score": 0.20,
            "confidence": 0.60,
            "detail": "CLIP score",
            "inference_time": 0.1,
        }
        ens_res = EnsembleResult(
            available=True,
            results=[
                mock_spec,
                ModelResult(True, "openai/clip-vit-base-patch32", 0.20, 0.60, "CLIP", 0.1),
            ],
            ensemble_score=0.80 * 0.15 + 0.20 * 0.20,
            ensemble_confidence=0.68,
            agreement_score=0.95,
            disagreement=False,
            inference_time_total=0.15,
            weights={"umm-maybe/AI-image-detector": 0.80, "openai/clip-vit-base-patch32": 0.20},
            detail="Ensemble summary",
            clip_result=mock_clip,
            specialized_result=mock_spec,
        )

        fused = fuse_signals(
            self.dummy_signals,
            ens_res,
            self.dummy_patch,
            self.dummy_ctype,
            prov_data={},
            file_path="real_camera_photo.jpg",
        )

        verdict = fused["verdict"]
        level = fused.get("debugAnalysis", {}).get("decision_hierarchy_level_triggered")
        self.assertEqual(verdict, "LIKELY_AUTHENTIC")
        self.assertEqual(level, "LEVEL_3_SPECIALIZED_DETECTOR")

    def test_strong_specialized_detector_yields_likely_ai(self):
        """Case D: When specialized detector has high probability (0.85), yields LIKELY_AI at Level 3."""
        mock_spec = ModelResult(
            available=True,
            model_name="umm-maybe/AI-image-detector",
            ai_probability=0.85,
            confidence=0.70,
            detail="Specialized score",
            inference_time=0.05,
        )
        mock_clip = {
            "available": True,
            "status": "active",
            "real_prompt_scores": {"real camera": 0.20},
            "ai_prompt_scores": {"ai generated": 0.80},
            "aggregate_score": 0.80,
            "confidence": 0.60,
            "detail": "CLIP score",
            "inference_time": 0.1,
        }
        ens_res = EnsembleResult(
            available=True,
            results=[
                mock_spec,
                ModelResult(True, "openai/clip-vit-base-patch32", 0.80, 0.60, "CLIP", 0.1),
            ],
            ensemble_score=0.84,
            ensemble_confidence=0.68,
            agreement_score=0.95,
            disagreement=False,
            inference_time_total=0.15,
            weights={"umm-maybe/AI-image-detector": 0.80, "openai/clip-vit-base-patch32": 0.20},
            detail="Ensemble summary",
            clip_result=mock_clip,
            specialized_result=mock_spec,
        )

        fused = fuse_signals(
            self.dummy_signals,
            ens_res,
            self.dummy_patch,
            self.dummy_ctype,
            prov_data={},
            file_path="ai_render.jpg",
        )

        self.assertEqual(fused["verdict"], "LIKELY_AI")
        self.assertEqual(fused.get("debugAnalysis", {}).get("decision_hierarchy_level_triggered"), "LEVEL_3_SPECIALIZED_DETECTOR")

    def test_ml_signal_weight_not_squashed(self):
        """Case E: _dynamic_signal_weight does not crush ML classifier weight to zero for 0.60 probability."""
        calibrated, conf, calib_dict = _calibrate_ml_probability(0.60)
        self.assertGreaterEqual(conf, 0.50)

        ml_sig = SignalResult(
            key="ml_umm_maybe",
            score=calibrated,
            detail="Specialized model probability",
            reliability="medium",
            category="ml_classifier",
            ensemble_multiplier=1.0,
            confidence=conf,
        )
        weight, reason = _dynamic_signal_weight(ml_sig)
        # Weight should retain a healthy portion of base weight (base is 0.5 * 0.7 = 0.35)
        self.assertGreater(weight, 0.15)


if __name__ == "__main__":
    unittest.main()
