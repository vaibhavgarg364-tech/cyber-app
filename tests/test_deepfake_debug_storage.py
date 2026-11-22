import asyncio
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
from fastapi import UploadFile

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from routes import deepfake_pipeline, detectors
from routes.deepfake_pipeline import PatchForensicEngine, PatchForensicResult, PatchResult
from routes.utils import download_media_from_url


class TestDeepfakeDebugStorage(unittest.TestCase):
    def test_module_default_and_explicit_environment_configuration(self):
        for value, expected in ((None, "False"), ("true", "True")):
            with self.subTest(value=value):
                environment = os.environ.copy()
                environment.pop("VEYRON_DEBUG_FACES", None)
                environment["PYTHONDONTWRITEBYTECODE"] = "1"
                if value is not None:
                    environment["VEYRON_DEBUG_FACES"] = value
                subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        (
                            f"import sys; sys.path.insert(0, {str(BACKEND_DIR)!r}); "
                            "from routes.deepfake_pipeline import DEBUG_MODE; "
                            f"assert DEBUG_MODE is {expected}"
                        ),
                    ],
                    cwd=PROJECT_ROOT,
                    env=environment,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

    def test_debug_images_are_disabled_by_default(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(deepfake_pipeline._debug_faces_enabled())
        with patch.dict(os.environ, {"VEYRON_DEBUG_FACES": "false"}):
            self.assertFalse(deepfake_pipeline._debug_faces_enabled())
        with patch.dict(os.environ, {"VEYRON_DEBUG_FACES": "true"}):
            self.assertTrue(deepfake_pipeline._debug_faces_enabled())
        with patch.dict(os.environ, {"VEYRON_DEBUG_FACES": "1"}):
            self.assertTrue(deepfake_pipeline._debug_faces_enabled())

    def test_detection_and_heatmap_do_not_write_images_when_debug_is_disabled(self):
        image = np.full((64, 64, 3), 127, dtype=np.uint8)
        patch_result = PatchForensicResult(
            available=True,
            mean_score=0.8,
            peak_score=0.9,
            suspicious_density=0.5,
            clustering_score=0.5,
            patches=[
                PatchResult(
                    x=0,
                    y=0,
                    size=32,
                    synthetic_score=0.8,
                    confidence=0.9,
                    residuals={},
                    is_suspicious=True,
                )
            ],
        )

        with tempfile.TemporaryDirectory() as output_dir:
            debug_dir = Path(output_dir) / "debug_outputs"
            with (
                patch.object(deepfake_pipeline, "DEBUG_MODE", False),
                patch.object(deepfake_pipeline, "DEBUG_OUTPUT_DIR", debug_dir),
                patch.object(deepfake_pipeline, "mp_available", True),
                patch.object(
                    deepfake_pipeline,
                    "_run_mediapipe_detector",
                    return_value=[object()],
                ),
                patch.object(
                    deepfake_pipeline,
                    "_extract_detection_box",
                    return_value=(16, 16, 24, 24, 0.9),
                ),
            ):
                faces, boxes, debug_info = deepfake_pipeline._detect_faces_mediapipe(
                    image, "test-operation"
                )
                heatmap_path = PatchForensicEngine().generate_heatmap(image, patch_result)

            self.assertEqual(len(faces), 1)
            self.assertEqual(len(boxes), 1)
            self.assertIsNone(debug_info["debug_overlay"])
            self.assertIsNone(heatmap_path)
            self.assertFalse(debug_dir.exists())

    def test_explicit_debug_mode_writes_face_and_heatmap_artifacts(self):
        image = np.full((128, 128, 3), 127, dtype=np.uint8)
        patch_result = PatchForensicResult(
            available=True,
            mean_score=0.8,
            peak_score=0.9,
            suspicious_density=0.5,
            clustering_score=0.5,
            patches=[
                PatchResult(
                    x=0,
                    y=0,
                    size=128,
                    synthetic_score=0.8,
                    confidence=0.9,
                    residuals={},
                    is_suspicious=True,
                )
            ],
        )

        with tempfile.TemporaryDirectory() as output_dir:
            debug_dir = Path(output_dir) / "debug_outputs"
            with (
                patch.object(deepfake_pipeline, "DEBUG_MODE", True),
                patch.object(deepfake_pipeline, "DEBUG_OUTPUT_DIR", debug_dir),
                patch.object(deepfake_pipeline, "mp_available", True),
                patch.object(
                    deepfake_pipeline,
                    "_run_mediapipe_detector",
                    return_value=[object()],
                ),
                patch.object(
                    deepfake_pipeline,
                    "_extract_detection_box",
                    return_value=(32, 32, 48, 48, 0.9),
                ),
            ):
                _, _, debug_info = deepfake_pipeline._detect_faces_mediapipe(
                    image, "debug-operation"
                )
                heatmap_path = PatchForensicEngine().generate_heatmap(
                    image, patch_result, "debug-operation"
                )

            self.assertTrue(Path(debug_info["debug_overlay"]).is_file())
            self.assertTrue(Path(heatmap_path).is_file())
            self.assertGreaterEqual(len(list(debug_dir.glob("*.jpg"))), 5)

    def test_interrupted_debug_image_write_removes_partial_output(self):
        with tempfile.TemporaryDirectory() as output_dir:
            debug_dir = Path(output_dir) / "debug_outputs"

            def interrupted_write(path, _image):
                Path(path).write_bytes(b"partial")
                raise asyncio.CancelledError()

            with (
                patch.object(deepfake_pipeline, "DEBUG_MODE", True),
                patch.object(deepfake_pipeline, "DEBUG_OUTPUT_DIR", debug_dir),
                patch(
                    "routes.deepfake_pipeline.cv2.imwrite",
                    side_effect=interrupted_write,
                ),
                self.assertRaises(asyncio.CancelledError),
            ):
                deepfake_pipeline._save_debug_image(
                    np.zeros((8, 8, 3), dtype=np.uint8),
                    "partial",
                    "interrupted",
                )

            self.assertEqual(list(debug_dir.glob("*.jpg")), [])

    def test_failed_or_interrupted_pipeline_removes_partial_debug_artifacts(self):
        for interruption in (RuntimeError("analysis failed"), asyncio.CancelledError()):
            with self.subTest(interruption=type(interruption).__name__):
                with tempfile.TemporaryDirectory() as output_dir:
                    debug_dir = Path(output_dir) / "debug_outputs"

                    def fail_after_writing(file_path):
                        self.assertEqual(file_path, "input.jpg")
                        path = deepfake_pipeline._save_debug_image(
                            np.zeros((8, 8, 3), dtype=np.uint8),
                            "partial",
                            "operation",
                        )
                        self.assertTrue(Path(path).is_file())
                        raise interruption

                    with (
                        patch.object(deepfake_pipeline, "DEBUG_MODE", True),
                        patch.object(deepfake_pipeline, "DEBUG_OUTPUT_DIR", debug_dir),
                        patch.object(
                            deepfake_pipeline,
                            "_run_forensic_pipeline",
                            side_effect=fail_after_writing,
                        ),
                        self.assertRaises(type(interruption)),
                    ):
                        deepfake_pipeline.run_forensic_pipeline("input.jpg")

                    self.assertEqual(list(debug_dir.glob("*.jpg")), [])


class TestDeepfakeTemporaryFileCleanup(unittest.IsolatedAsyncioTestCase):
    async def _run_upload(self, detector_side_effect):
        temp_paths = []
        self.captured_temp_paths = temp_paths
        original_named_temporary_file = tempfile.NamedTemporaryFile

        def capture_temporary_file(*args, **kwargs):
            temp_file = original_named_temporary_file(*args, **kwargs)
            temp_paths.append(Path(temp_file.name))
            return temp_file

        upload = UploadFile(filename="uploaded.jpg", file=io.BytesIO(b"image-bytes"))
        with (
            patch.object(
                detectors.tempfile,
                "NamedTemporaryFile",
                side_effect=capture_temporary_file,
            ),
            patch.object(
                detectors,
                "detect_deepfake_file",
                side_effect=detector_side_effect,
            ),
        ):
            result = await detectors.detect_deepfake(file=upload)

        return result, temp_paths

    async def test_uploaded_image_temp_file_is_removed_after_success(self):
        def analyze(file_path):
            self.assertTrue(Path(file_path).is_file())
            return {"verdict": "LIKELY_AI", "confidencePercent": 75}

        _, temp_paths = await self._run_upload(analyze)
        self.assertEqual(len(temp_paths), 1)
        self.assertFalse(temp_paths[0].exists())

    async def test_uploaded_image_temp_file_is_removed_after_failure(self):
        _, temp_paths = await self._run_upload(
            RuntimeError("simulated detector failure")
        )
        self.assertEqual(len(temp_paths), 1)
        self.assertFalse(temp_paths[0].exists())

    async def test_uploaded_image_temp_file_is_removed_on_cancellation(self):
        with self.assertRaises(asyncio.CancelledError):
            await self._run_upload(
                asyncio.CancelledError()
            )
        self.assertEqual(len(self.captured_temp_paths), 1)
        self.assertFalse(self.captured_temp_paths[0].exists())

    async def test_downloaded_image_temp_file_is_removed_after_processing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir) / "downloaded.jpg"
            temp_path.write_bytes(b"image-bytes")

            def analyze(file_path):
                self.assertEqual(file_path, str(temp_path))
                self.assertTrue(temp_path.is_file())
                return {"verdict": "LIKELY_AI", "confidencePercent": 75}

            with (
                patch.object(
                    detectors,
                    "download_media_from_url",
                    return_value=(str(temp_path), None),
                ),
                patch.object(detectors, "detect_deepfake_file", side_effect=analyze),
            ):
                await detectors.detect_deepfake(
                    mediaUrl="https://example.test/image.jpg",
                    file=None,
                )

            self.assertFalse(temp_path.exists())

    def test_partial_url_download_is_removed_after_failure(self):
        temp_paths = []
        original_mkstemp = tempfile.mkstemp

        def capture_mkstemp(*args, **kwargs):
            fd, path = original_mkstemp(*args, **kwargs)
            temp_paths.append(Path(path))
            return fd, path

        class InterruptedResponse:
            headers = {"Content-Type": "image/jpeg"}

            def raise_for_status(self):
                pass

            def iter_content(self, chunk_size):
                if chunk_size <= 0:
                    raise AssertionError("Expected a positive chunk size")
                yield b"partial image bytes"
                raise OSError("simulated interrupted download")

        with (
            patch.object(
                detectors.tempfile,
                "mkstemp",
                side_effect=capture_mkstemp,
            ),
            patch("routes.utils.requests.get", return_value=InterruptedResponse()),
        ):
            path, error = download_media_from_url("https://example.test/image.jpg")

        self.assertIsNone(path)
        self.assertIsNotNone(error)
        self.assertEqual(len(temp_paths), 1)
        self.assertFalse(temp_paths[0].exists())


class TestProductionDeepfakeConfiguration(unittest.TestCase):
    def test_production_compose_and_example_disable_debug_storage(self):
        compose = (PROJECT_ROOT / "docker-compose.prod.yml").read_text(
            encoding="utf-8"
        )
        dockerignore = (BACKEND_DIR / ".dockerignore").read_text(encoding="utf-8")
        production_example = (PROJECT_ROOT / ".env.prod.example").read_text(
            encoding="utf-8"
        )

        self.assertRegex(
            compose,
            r'(?m)^\s+VEYRON_DEBUG_FACES:\s*["\']?false["\']?\s*$',
        )
        self.assertRegex(
            production_example,
            r"(?m)^VEYRON_DEBUG_FACES=false\s*$",
        )
        self.assertNotIn("./backend:/app", compose)
        self.assertNotIn("debug_outputs", compose)
        self.assertIn("debug_outputs/", dockerignore.splitlines())


if __name__ == "__main__":
    unittest.main()
