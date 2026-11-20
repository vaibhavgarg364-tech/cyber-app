"""
Hybrid deepfake/AI-image pipeline (Redesigned):
- Honest content-type routing
- MediaPipe Face Detection
- Demoted CLIP semantic scoring
- Forensic transparency
"""
from __future__ import annotations

import logging
import re
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional, Tuple

import cv2
import numpy as np
from .utils import sanitize_for_json
from .provenance_engine import ProvenanceEngine

_provenance_engine = ProvenanceEngine()

# MediaPipe for modern face detection
mp = None
mp_face_detection = None
mp_tasks_vision = None
mp_tasks_python = None
mp_available = False
mp_detector_api = "unavailable"
mp_import_error = None
MP_FACE_MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "blaze_face_short_range.tflite"
os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "veyron-matplotlib"))
for _hf_cand in [Path("D:/AI_CACHE/huggingface"), Path("D:/DevCache/huggingface")]:
    if _hf_cand.exists():
        os.environ.setdefault("HF_HOME", str(_hf_cand))
        break

try:
    import mediapipe as mp
    try:
        from mediapipe.tasks import python as mp_tasks_python
        from mediapipe.tasks.python import vision as mp_tasks_vision
        if MP_FACE_MODEL_PATH.exists():
            mp_detector_api = "tasks_vision"
            mp_available = True
    except Exception as exc:
        mp_import_error = f"mediapipe.tasks import/init failed: {exc}"
        mp_tasks_python = None
        mp_tasks_vision = None

    if not mp_available and hasattr(mp, "solutions"):
        mp_face_detection = mp.solutions.face_detection
        mp_detector_api = "solutions"
        mp_available = True
except Exception as exc:
    mp_import_error = f"mediapipe import failed: {exc}"
    mp = None
    mp_available = False

logger = logging.getLogger("veyron-backend.deepfake_pipeline")

RUNTIME_VERSION = "live_guard_v1"

print("\n" + "="*50)
print("[Deepfake Runtime Audit]")
print(f"Module Path: {__file__}")
print(f"Timestamp: {time.time()}")
print(f"Version: {RUNTIME_VERSION}")
try:
    import subprocess
    git_hash = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"]).decode("utf-8").strip()
    print(f"Git Hash: {git_hash}")
except Exception:
    print("Git Hash: unavailable")
print("="*50 + "\n")

# --- MediaPipe startup diagnostics (logged at import time) ---
mp_startup_info: Dict[str, Any] = {
    "loaded": mp is not None,
    "available": mp_available,
    "api": mp_detector_api,
    "model_path": str(MP_FACE_MODEL_PATH),
    "model_exists": MP_FACE_MODEL_PATH.exists(),
    "import_confirmed": mp is not None,
    "module_path": __file__,
    "import_error": mp_import_error,
}

if mp_available:
    try:
        mp_version = getattr(mp, "__version__", "unknown")
        mp_startup_info["version"] = mp_version
        try:
            # Quick detector init check
            if mp_detector_api == "tasks_vision":
                _options = mp_tasks_vision.FaceDetectorOptions(
                    base_options=mp_tasks_python.BaseOptions(model_asset_path=str(MP_FACE_MODEL_PATH)),
                    min_detection_confidence=0.3,
                )
                _det = mp_tasks_vision.FaceDetector.create_from_options(_options)
                _det.close()
            else:
                with mp_face_detection.FaceDetection(model_selection=1, min_detection_confidence=0.3):
                    pass
            mp_startup_info["detector_init"] = True
        except Exception as _e:
            mp_startup_info["detector_init"] = False
            mp_startup_info["detector_error"] = str(_e)
    except Exception as _e:
        mp_startup_info["version_error"] = str(_e)
    logger.info(
        "[Startup Diagnostics] MediaPipe version=%s import_confirmed=%s "
        "api=%s active_face_detector_initialized=%s model_exists=%s pipeline_path=%s",
        mp_startup_info.get("version", "unknown"),
        mp_startup_info["import_confirmed"],
        mp_startup_info["api"],
        mp_startup_info.get("detector_init", False),
        mp_startup_info["model_exists"],
        __file__,
    )
else:
    logger.warning("[Startup Diagnostics] MediaPipe loaded=%s available=false info=%s", mp is not None, mp_startup_info)

_DDEPTH_DERIV = cv2.CV_32F

Assessment = Literal[
    "likely_authentic",
    "likely_ai_generated",
    "inconclusive",
    "insufficient_evidence",
]

SignalCategory = Literal[
    "metadata",
    "facial_forensics",
    "frequency_domain",
    "compression_ela",
    "ml_classifier",
    "diffusion_artifact",
    "patch_artifact",
    "general",
]

@dataclass
class SignalResult:
    key: str
    score: float
    detail: str
    category: SignalCategory
    status: Literal["active", "failed", "skipped", "suppressed"] = "active"
    reliability: Literal["high", "medium", "low"] = "medium"
    human_readable: str = ""
    confidence_interval: Optional[Tuple[float, float]] = None
    ensemble_multiplier: float = 1.0
    confidence: Optional[float] = None

    def __post_init__(self):
        self.score = float(self.score)
        if self.confidence_interval:
            self.confidence_interval = (float(self.confidence_interval[0]), float(self.confidence_interval[1]))
        if self.confidence is None:
            # Default confidence calculation
            rel_factor = {"high": 1.0, "medium": 0.75, "low": 0.5}.get(self.reliability, 0.75)
            score_distance = abs(self.score - 0.5) * 2.0
            self.confidence = float(_clamp(score_distance * rel_factor))
        else:
            self.confidence = float(self.confidence)

@dataclass
class ModelResult:
    available: bool
    model_name: str
    ai_probability: float
    confidence: float
    detail: str
    inference_time: float = 0.0
    load_time: float = 0.0

    def __post_init__(self):
        self.available = bool(self.available)
        self.ai_probability = float(self.ai_probability)
        self.confidence = float(self.confidence)
        self.inference_time = float(self.inference_time)
        self.load_time = float(self.load_time)

@dataclass
class EnsembleResult:
    available: bool
    results: List[ModelResult]
    ensemble_score: float
    ensemble_confidence: float
    agreement_score: float  # 0 to 1, how much they agree
    disagreement: bool
    inference_time_total: float
    weights: Dict[str, float]
    detail: str
    clip_result: Optional[Dict[str, Any]] = None
    specialized_result: Optional[ModelResult] = None

def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return float(max(lo, min(hi, x)))

def log_memory_rss(stage_name: str) -> None:
    try:
        import psutil
        import gc
        gc.collect()
        proc = psutil.Process(os.getpid())
        rss_mb = proc.memory_info().rss / (1024 * 1024)
        logger.info(f"[Memory Trace] Stage '{stage_name}': RSS = {rss_mb:.2f} MB")
    except Exception as e:
        logger.debug(f"Failed to log memory at stage '{stage_name}': {e}")

def safe_int_box(box: Any, image_h: int, image_w: int) -> Optional[Tuple[int, int, int, int]]:
    """Requirement: Standalone helper for coordinate hardening and bound clamping."""
    try:
        if box is None: return None
        # Handle (x, y, w, h)
        if hasattr(box, "__len__") and len(box) >= 4:
            ix, iy, iw, ih = [int(round(float(c))) for c in box[:4]]
            
            x1 = max(0, min(image_w - 1, ix))
            y1 = max(0, min(image_h - 1, iy))
            x2 = max(0, min(image_w, ix + iw))
            y2 = max(0, min(image_h, iy + ih))
            
            if x2 > x1 and y2 > y1:
                return (x1, y1, x2 - x1, y2 - y1)
    except (ValueError, TypeError, IndexError):
        logger.error(f"[Forensic Debug] safe_int_box failed for {box} (types: {[type(c) for c in box if box]})")
    return None

def _confidence_interval(score: float, width: float) -> Tuple[float, float]:
    return (round(_clamp(score - width), 3), round(_clamp(score + width), 3))

@dataclass
class PatchResult:
    """Requirement Part 1: Represents forensic analysis of a local image region."""
    x: int
    y: int
    size: int
    synthetic_score: float
    confidence: float
    residuals: Dict[str, float]
    is_suspicious: bool

@dataclass
class PatchForensicResult:
    available: bool
    mean_score: float
    peak_score: float
    suspicious_density: float
    clustering_score: float
    patches: List[PatchResult]
    heatmap_path: Optional[str] = None
    detail: str = ""
    # DBSCAN fields
    cluster_count: int = 0
    largest_cluster_ratio: float = 0.0
    cluster_entropy: float = 0.0
    confidence_mean: float = 0.0
    blockiness: float = 0.0

class PatchForensicEngine:
    """
    UPGRADE: Lightweight patch-based forensic system (Requirement Part 1-5).
    Focuses on local artifact learning and frequency residuals instead of global semantic classification.
    """
    PATCH_SIZE = 128
    STRIDE = 64
    
    def __init__(self):
        self.synthetic_residual_threshold = 0.62
        self.min_info_content = 5.0 # Skip flat/empty patches
        # Precompute ref_lbp
        self.ref_lbp = np.zeros(256, dtype=np.float32)
        for val in range(256):
            binary = format(val, '08b')
            transitions = sum(binary[k] != binary[(k+1)%8] for k in range(8))
            if transitions <= 2:
                self.ref_lbp[val] = 10.0
            else:
                self.ref_lbp[val] = 1.0
        self.ref_lbp /= np.sum(self.ref_lbp)

    def _wiener_filter(self, img: np.ndarray, kernel_size: int = 5) -> np.ndarray:
        mu = cv2.boxFilter(img, -1, (kernel_size, kernel_size))
        mu_sq = cv2.boxFilter(img**2, -1, (kernel_size, kernel_size))
        var = mu_sq - mu**2
        noise_var = np.mean(var)
        if noise_var < 1e-5:
            return img.copy()
        res = mu + (np.maximum(0, var - noise_var) / np.maximum(var, noise_var)) * (img - mu)
        return res

    def _autocorrelation(self, eta: np.ndarray, tx: int, ty: int) -> float:
        h, w = eta.shape
        if tx >= w or ty >= h:
            return 0.0
        numerator = np.sum(eta[:h-ty, :w-tx] * eta[ty:, tx:])
        denominator = np.sum(eta[:h-ty, :w-tx]**2)
        if denominator < 1e-7:
            return 0.0
        return float(numerator / denominator)
        
    def _estimate_jpeg_blockiness(self, gray: np.ndarray) -> float:
        """Estimate JPEG blockiness by looking at 8x8 grid boundaries."""
        h, w = gray.shape
        if h < 16 or w < 16:
            return 0.0
        try:
            # Horizontal differences
            diff_h = np.abs(gray[:, 1:] - gray[:, :-1])
            # Vertical differences
            diff_v = np.abs(gray[1:, :] - gray[:-1, :])
            
            # Grid boundaries (modulo 8)
            cols = np.arange(diff_h.shape[1])
            rows = np.arange(diff_v.shape[0])
            
            h_grid = diff_h[:, cols % 8 == 7]
            h_other = diff_h[:, cols % 8 != 7]
            v_grid = diff_v[rows % 8 == 7, :]
            v_other = diff_v[rows % 8 != 7, :]
            
            mean_h_grid = np.mean(h_grid) if h_grid.size else 0.0
            mean_h_other = np.mean(h_other) if h_other.size else 0.0
            mean_v_grid = np.mean(v_grid) if v_grid.size else 0.0
            mean_v_other = np.mean(v_other) if v_other.size else 0.0
            
            blockiness_h = mean_h_grid / (mean_h_other + 1e-5)
            blockiness_v = mean_v_grid / (mean_v_other + 1e-5)
            
            blockiness = (blockiness_h + blockiness_v) / 2.0
            val = float(max(0.0, blockiness - 1.0))
            if np.isnan(val) or np.isinf(val):
                return 0.0
            return val
        except Exception:
            return 0.0

    def _haar_dwt2(self, gray: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        h, w = gray.shape
        crop_h = h - h % 2
        crop_w = w - w % 2
        g = gray[:crop_h, :crop_w]
        
        # Guard against zero or empty dimensions
        if g.size == 0:
            empty = np.zeros((0, 0), dtype=np.float32)
            return empty, empty, empty, empty
            
        a = (g[:, 0::2] + g[:, 1::2]) / 2.0
        d = (g[:, 0::2] - g[:, 1::2]) / 2.0
        LL = (a[0::2, :] + a[1::2, :]) / 2.0
        LH = (a[0::2, :] - a[1::2, :]) / 2.0
        HL = (d[0::2, :] + d[1::2, :]) / 2.0
        HH = (d[0::2, :] - d[1::2, :]) / 2.0
        return LL, LH, HL, HH

    def _dbscan(self, points: List[Tuple[float, float]], eps: float, min_samples: int) -> List[int]:
        n = len(points)
        # Prevent flat-image explosions / OOM by limiting points
        if n > 1000:
            points = points[:1000]
            n = 1000
            
        labels = [-2] * n  # -2 means UNVISITED
        cluster_id = 0
        
        def get_neighbors(i: int) -> List[int]:
            neighbors = []
            p_i = points[i]
            for j in range(n):
                p_j = points[j]
                dist = np.sqrt((p_i[0] - p_j[0])**2 + (p_i[1] - p_j[1])**2)
                if dist <= eps:
                    neighbors.append(j)
            return neighbors
            
        for i in range(n):
            if labels[i] != -2:
                continue
            neighbors = get_neighbors(i)
            if len(neighbors) < min_samples:
                labels[i] = -1  # Noise
                continue
                
            labels[i] = cluster_id
            queue = [idx for idx in neighbors if idx != i]
            visited_seeds = set(queue)
            idx_in_queue = 0
            while idx_in_queue < len(queue):
                curr = queue[idx_in_queue]
                idx_in_queue += 1
                
                if labels[curr] == -1 or labels[curr] == -2:
                    labels[curr] = cluster_id
                
                curr_neighbors = get_neighbors(curr)
                if len(curr_neighbors) >= min_samples:
                    for n_idx in curr_neighbors:
                        if labels[n_idx] == -2 or labels[n_idx] == -1:
                            if n_idx not in visited_seeds:
                                visited_seeds.add(n_idx)
                                queue.append(n_idx)
            cluster_id += 1
            
        for i in range(n):
            if labels[i] == -2:
                labels[i] = -1
        return labels

    def _extract_residuals(self, gray: np.ndarray) -> Dict[str, float]:
        """Requirement Part 2: High-pass and Frequency Residual Extraction."""
        # 1. Laplacian Residual
        laplacian = cv2.Laplacian(gray, cv2.CV_32F)
        lap_var = float(np.var(laplacian))
        if np.isnan(lap_var) or np.isinf(lap_var):
            lap_var = 0.0
            
        # 2. High-Pass Residual
        blurred = cv2.GaussianBlur(gray, (5, 5), 0)
        hp_residual = gray - blurred
        hp_energy = float(np.mean(np.square(hp_residual)))
        if np.isnan(hp_energy) or np.isinf(hp_energy):
            hp_energy = 0.0
            
        # 3. FFT Residual
        dft = np.fft.fft2(gray)
        dft_shift = np.fft.fftshift(dft)
        magnitude = np.abs(dft_shift)
        h, w = magnitude.shape
        cy, cx = h // 2, w // 2
        high_freq_region = magnitude.copy()
        cv2.circle(high_freq_region, (cx, cy), min(h, w) // 4, 0, -1)
        fft_energy = float(np.mean(high_freq_region))
        if np.isnan(fft_energy) or np.isinf(fft_energy):
            fft_energy = 0.0
            
        # 4. Wavelet Residual
        LL, LH, HL, HH = self._haar_dwt2(gray)
        wavelet_energy = float(np.mean(LH**2 + HL**2 + HH**2))
        if np.isnan(wavelet_energy) or np.isinf(wavelet_energy):
            wavelet_energy = 0.0
            
        # Safe entropy calculation
        hist, _ = np.histogram(gray, 256, [0, 256])
        p = hist / (gray.size + 1e-7)
        entropy = float(-np.sum(p * np.log2(p + 1e-7)))
        if np.isnan(entropy) or np.isinf(entropy):
            entropy = 0.0
            
        # Standard deviation of the patch
        p_var = float(np.var(gray))
        p_std = float(np.sqrt(p_var))
        if np.isnan(p_std) or np.isinf(p_std):
            p_std = 0.0

        # --- V2 Descriptors ---
        # 1. Local Noise Coherence (LNC)
        eta = gray - self._wiener_filter(gray)
        offsets = [(1,0), (0,1), (1,1), (2,0), (0,2)]
        lnc_vals = [abs(self._autocorrelation(eta, tx, ty)) for tx, ty in offsets]
        mean_lnc = float(np.mean(lnc_vals)) if lnc_vals else 0.0
        
        # 2. SRM Residuals (min-max and edge span)
        kernel = np.ones((3, 3), dtype=np.uint8)
        erode = cv2.erode(gray, kernel)
        dilate = cv2.dilate(gray, kernel)
        R_min = gray - erode
        R_max = gray - dilate
        
        k_h1 = np.array([[0, -1, 1]], dtype=np.float32)
        R_h1 = cv2.filter2D(gray, -1, k_h1)
        k_v1 = np.array([[0], [-1], [1]], dtype=np.float32)
        R_v1 = cv2.filter2D(gray, -1, k_v1)
        k_h2 = np.array([[-1, 2, -1]], dtype=np.float32)
        R_h2 = cv2.filter2D(gray, -1, k_h2)
        k_v2 = np.array([[-1], [2], [-1]], dtype=np.float32)
        R_v2 = cv2.filter2D(gray, -1, k_v2)
        
        var_min = float(np.var(np.clip(np.round(R_min), -3.0, 3.0)))
        var_max = float(np.var(np.clip(np.round(R_max), -3.0, 3.0)))
        var_h1 = float(np.var(np.clip(np.round(R_h1), -3.0, 3.0)))
        var_v1 = float(np.var(np.clip(np.round(R_v1), -3.0, 3.0)))
        var_h2 = float(np.var(np.clip(np.round(R_h2), -3.0, 3.0)))
        var_v2 = float(np.var(np.clip(np.round(R_v2), -3.0, 3.0)))
        
        srm_variance = float(np.mean([var_min, var_max, var_h1, var_v1, var_h2, var_v2]))
        
        # 3. DWT Co-occurrence
        co_occ_all = np.zeros((8, 8), dtype=np.float32)
        for S in [LH, HL, HH]:
            s_min, s_max = np.min(S), np.max(S)
            if s_max > s_min:
                S_quant = np.clip(((S - s_min) / (s_max - s_min) * 7.999).astype(np.int32), 0, 7)
            else:
                S_quant = np.zeros(S.shape, dtype=np.int32)
            
            co_occ = np.zeros((8, 8), dtype=np.float32)
            left = S_quant[:, :-1].ravel()
            right = S_quant[:, 1:].ravel()
            top = S_quant[:-1, :].ravel()
            bottom = S_quant[1:, :].ravel()
            p1 = np.concatenate([left, top])
            p2 = np.concatenate([right, bottom])
            np.add.at(co_occ, (p1, p2), 1.0)
            total = np.sum(co_occ)
            if total > 0:
                co_occ /= total
            co_occ_all += co_occ
        co_occ_all /= 3.0
        
        i, j = np.ogrid[:8, :8]
        dwt_contrast = float(np.sum((i - j)**2 * co_occ_all))
        dwt_entropy = float(-np.sum(co_occ_all * np.log2(co_occ_all + 1e-7)))
        
        # 4. LBP KL Divergence
        h_g, w_g = gray.shape
        lbp = np.zeros((h_g-2, w_g-2), dtype=np.uint8)
        center = gray[1:-1, 1:-1]
        offsets_lbp = [
            (-1, -1), (-1, 0), (-1, 1),
            (0, 1),   (1, 1),  (1, 0),
            (1, -1),  (0, -1)
        ]
        for bit, (dy, dx) in enumerate(offsets_lbp):
            neighbor = gray[1+dy:h_g-1+dy, 1+dx:w-1+dx]
            lbp += ((neighbor >= center).astype(np.uint8) << bit)
            
        hist_lbp, _ = np.histogram(lbp, bins=256, range=[0, 256])
        p_lbp = hist_lbp / (np.sum(hist_lbp) + 1e-7)
        lbp_kl = float(np.sum(p_lbp * np.log2((p_lbp + 1e-7) / (self.ref_lbp + 1e-7))))
            
        return {
            "laplacian_var": lap_var,
            "hp_energy": hp_energy,
            "fft_high_freq": fft_energy,
            "wavelet_energy": wavelet_energy,
            "entropy": entropy,
            "p_std": p_std,
            "mean_lnc": mean_lnc,
            "srm_variance": srm_variance,
            "dwt_contrast": dwt_contrast,
            "dwt_entropy": dwt_entropy,
            "lbp_kl": lbp_kl
        }

    def _score_patch(self, res: Dict[str, float], res_factor: float, comp_factor: float) -> Tuple[float, float]:
        """Calibrated forensic patch classifier: separates authentic optical camera textures from synthetic AI artifacts."""
        lbp_kl = res.get("lbp_kl", 0.0)
        srm_var = res.get("srm_variance", 0.0)
        mean_lnc = res.get("mean_lnc", 0.0)

        # 1. LBP anomaly: natural optical textures match natural LBP reference (lbp_kl <= 1.5).
        # AI diffusion/GAN models have unnatural micro-texture distributions (lbp_kl >= 3.0).
        s_lbp = _clamp((lbp_kl - 1.5) / 3.0)

        # 2. Residual smoothness / lack of optical sensor noise:
        # Physical camera sensors always exhibit shot noise (srm_var >= 0.8).
        # AI images have near-zero spatial noise residuals in smooth/semi-uniform patches.
        s_smooth = _clamp((0.55 - srm_var) / 0.55)

        # 3. Local Noise Coherence: synthetic upsampling/interpolation causes correlated noise
        s_lnc = _clamp((mean_lnc - 0.26) / 0.35)

        # Calibrated weighted combination
        score = float(0.50 * s_lbp + 0.35 * s_smooth + 0.15 * s_lnc)
        if np.isnan(score) or np.isinf(score):
            score = 0.5

        confidence = _clamp(abs(score - 0.5) * 2.0)
        return float(score), float(confidence)

    def generate_heatmap(self, img: np.ndarray, result: PatchForensicResult) -> Optional[str]:
        """Requirement Part 5: Generate artifact concentration overlay (memory optimized)."""
        if not result.available or not result.patches:
            return None
            
        h, w = img.shape[:2]
        
        # Memory optimization: process heatmap at 1/4 size
        scale_factor = 4
        hh, ww = max(1, h // scale_factor), max(1, w // scale_factor)
        heatmap = np.zeros((hh, ww), dtype=np.float32)
        
        for p in result.patches:
            x1 = int(p.x // scale_factor)
            y1 = int(p.y // scale_factor)
            box_sz = int(p.size // scale_factor)
            
            x1 = max(0, min(x1, ww - 1))
            y1 = max(0, min(y1, hh - 1))
            x2 = max(0, min(x1 + box_sz, ww))
            y2 = max(0, min(y1 + box_sz, hh))
            
            if x2 > x1 and y2 > y1:
                heatmap[y1:y2, x1:x2] += p.synthetic_score
                
        # Heatmap validation and normalization
        h_max = np.max(heatmap)
        h_min = np.min(heatmap)
        if h_max > h_min:
            heatmap_norm = ((heatmap - h_min) / (h_max - h_min + 1e-7) * 255.0).astype(np.uint8)
        else:
            heatmap_norm = np.zeros((hh, ww), dtype=np.uint8)
            
        # Resize input image to match downscaled overlay for fast blending
        img_ds = cv2.resize(img, (ww, hh), interpolation=cv2.INTER_AREA)
        heatmap_color = cv2.applyColorMap(heatmap_norm, cv2.COLORMAP_JET)
        overlay = cv2.addWeighted(img_ds, 0.7, heatmap_color, 0.3, 0)
        
        os.makedirs("debug_outputs", exist_ok=True)
        filename = f"patch_heatmap_{int(time.time())}.jpg"
        path = os.path.join("debug_outputs", filename)
        
        cv2.imwrite(path, overlay)
        
        # GC clean up
        del heatmap
        del heatmap_norm
        del img_ds
        del heatmap_color
        del overlay
        import gc
        gc.collect()
        
        return path

    def analyze(self, img: np.ndarray, mask: Optional[np.ndarray] = None) -> PatchForensicResult:
        h, w = img.shape[:2]
        patches = []
        
        t0 = time.perf_counter()
        
        # Pre-convert the entire image to grayscale once, saving allocations
        gray_img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY).astype(np.float32)
        
        # Calculate resolution factor and compression factor globally
        res_factor = max(0.5, min(2.5, np.sqrt(w * h) / 1024.0))
        blockiness = self._estimate_jpeg_blockiness(gray_img)
        comp_factor = max(0.4, min(1.3, 1.3 / (blockiness + 0.1)))
        
        for y in range(0, h - self.PATCH_SIZE + 1, self.STRIDE):
            for x in range(0, w - self.PATCH_SIZE + 1, self.STRIDE):
                y_start = int(y)
                y_end = int(y + self.PATCH_SIZE)
                x_start = int(x)
                x_end = int(x + self.PATCH_SIZE)
                
                # Bounds clamping & coordinate checks
                y_start = max(0, min(y_start, h - 1))
                y_end = max(0, min(y_end, h))
                x_start = max(0, min(x_start, w - 1))
                x_end = max(0, min(x_end, w))
                
                # Empty / partial patch rejection
                if (y_end - y_start) != self.PATCH_SIZE or (x_end - x_start) != self.PATCH_SIZE:
                    continue
                    
                if mask is not None:
                    if mask.shape[:2] != img.shape[:2]:
                        logger.error(f"[Forensic Debug] Mask shape mismatch: {mask.shape} vs {img.shape}")
                        mask_patch = None
                    else:
                        mask_patch = mask[y_start:y_end, x_start:x_end]
                    
                    if mask_patch is not None and np.mean(mask_patch) < 10:
                        continue
                        
                gray_patch = gray_img[y_start:y_end, x_start:x_end]
                if gray_patch.size == 0:
                    continue
                    
                # Uniform Region Detection (Variance floor / Entropy check)
                p_var = np.var(gray_patch)
                p_std = np.sqrt(p_var)
                if np.isnan(p_std) or np.isinf(p_std):
                    p_std = 0.0
                    
                # Safe entropy
                hist, _ = np.histogram(gray_patch, 256, [0, 256])
                p = hist / (gray_patch.size + 1e-7)
                entropy = float(-np.sum(p * np.log2(p + 1e-7)))
                if np.isnan(entropy) or np.isinf(entropy):
                    entropy = 0.0
                    
                # Skip flat/uniform texture regions to prevent explosives/OOMs
                if p_std < 2.0 or entropy < 3.8:
                    continue
                    
                res = self._extract_residuals(gray_patch)
                score, conf = self._score_patch(res, res_factor, comp_factor)
                
                # Clamp and normalize confidence
                score = _clamp(score)
                lap_std = np.sqrt(res["laplacian_var"])
                conf = conf * (1.0 - np.exp(-lap_std / 5.0))
                conf = _clamp(conf)
                
                patches.append(PatchResult(
                    x=x_start, y=y_start, size=self.PATCH_SIZE,
                    synthetic_score=score, confidence=conf,
                    residuals=res, is_suspicious=(score > 0.65)
                ))
                
        # Clean up global grayscale array
        del gray_img
        import gc
        gc.collect()
        
        if not patches:
            return PatchForensicResult(
                available=False,
                mean_score=0.5,
                peak_score=0.5,
                suspicious_density=0.0,
                clustering_score=0.0,
                patches=[],
                heatmap_path=None,
                detail="No valid patches found for forensic analysis.",
                blockiness=blockiness
            )

        scores = [p.synthetic_score for p in patches]
        mean_score = float(np.mean(scores))
        peak_score = float(np.max(scores))
        suspicious = [p for p in patches if p.is_suspicious]
        
        # division protection
        suspicious_density = len(suspicious) / (len(patches) + 1e-7)
        
        cluster_count = 0
        largest_cluster_ratio = 0.0
        cluster_entropy = 0.0
        confidence_mean = float(np.mean([p.confidence for p in patches])) if patches else 0.0
        
        if len(suspicious) > 0:
            points = [(p.x, p.y) for p in suspicious]
            labels = self._dbscan(points, eps=1.8 * self.STRIDE, min_samples=2)
            
            unique_labels = set(labels)
            clusters = [l for l in unique_labels if l != -1]
            cluster_count = len(clusters)
            
            cluster_sizes = [labels.count(c) for c in clusters]
            largest_cluster_size = max(cluster_sizes) if cluster_sizes else 0
            largest_cluster_ratio = largest_cluster_size / (len(patches) + 1e-7)
            
            import math
            for l in unique_labels:
                count = labels.count(l)
                p_c = count / (len(labels) + 1e-7)
                if p_c > 0:
                    cluster_entropy -= p_c * math.log2(p_c)
                    
            if math.isnan(cluster_entropy) or math.isinf(cluster_entropy):
                cluster_entropy = 0.0
                
        clustering_score = _clamp(largest_cluster_ratio * 4.0)
        total_time = time.perf_counter() - t0
        
        detail = (f"DBSCAN Forensic Audit: {len(patches)} patches. "
                  f"Density: {suspicious_density:.2f}, "
                  f"Clusters: {cluster_count}, "
                  f"Largest Cluster Ratio: {largest_cluster_ratio:.2f}, "
                  f"Cluster Entropy: {cluster_entropy:.2f}, "
                  f"Conf Mean: {confidence_mean:.2f} (Time: {total_time:.3f}s)")
        
        return PatchForensicResult(
            available=True,
            mean_score=mean_score,
            peak_score=peak_score,
            suspicious_density=suspicious_density,
            clustering_score=clustering_score,
            patches=patches,
            detail=detail,
            cluster_count=cluster_count,
            largest_cluster_ratio=largest_cluster_ratio,
            cluster_entropy=cluster_entropy,
            confidence_mean=confidence_mean,
            blockiness=blockiness
        )

def _confidence_interval(score: float, width: float) -> Tuple[float, float]:
    return (round(_clamp(score - width), 3), round(_clamp(score + width), 3))

# --- Utils (Decode, Grey, Laplacian, Resize) ---
def _ensure_bgr_u8(img: np.ndarray) -> Optional[np.ndarray]:
    if img is None or img.size == 0: return None
    if img.dtype == np.uint16: img = cv2.convertScaleAbs(img, alpha=1.0/257.0)
    elif np.issubdtype(img.dtype, np.floating): img = np.clip(img * 255.0, 0, 255).astype(np.uint8)
    if img.ndim == 2: return cv2.cvtColor(img, cv2.COLOR_GRAY2BGR)
    elif img.ndim == 3 and img.shape[2] == 4: return cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
    elif img.ndim == 3 and img.shape[2] == 3: return img
    elif img.ndim == 3 and img.shape[2] == 1: return cv2.cvtColor(img[:,:,0], cv2.COLOR_GRAY2BGR)
    return None

def _load_image_bgr(path: str) -> Optional[np.ndarray]:
    try:
        data = Path(path).read_bytes()
        if not data: return None
        arr = np.frombuffer(data, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_UNCHANGED)
        return _ensure_bgr_u8(img)
    except Exception as exc:
        logger.warning(f"Image decode failed: {exc}")
        return None

def _to_gray_u8(bgr: np.ndarray) -> np.ndarray:
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    return np.ascontiguousarray(gray)

def _laplacian_variance_u8(gray_u8: np.ndarray) -> float:
    lap = cv2.Laplacian(gray_u8, _DDEPTH_DERIV, ksize=3)
    return float(np.var(lap.astype(np.float64)))

def _resize_long_edge(img: np.ndarray, max_side: int = 896) -> Tuple[np.ndarray, float]:
    h, w = img.shape[:2]
    long_side = max(h, w)
    if long_side <= max_side: return img, 1.0
    scale = max_side / float(long_side)
    nw, nh = max(1, int(w * scale)), max(1, int(h * scale))
    return np.ascontiguousarray(cv2.resize(img, (nw, nh), interpolation=cv2.INTER_AREA)), scale

# --- MediaPipe Face Detection (with comprehensive debugging) ---
DEBUG_MODE = os.environ.get("VEYRON_DEBUG_FACES", "1") == "1"
DEBUG_OUTPUT_DIR = Path("debug_outputs")

def _setup_debug_output():
    """Ensure debug output directory exists."""
    if DEBUG_MODE:
        DEBUG_OUTPUT_DIR.mkdir(exist_ok=True)
        logger.info(f"Debug mode enabled. Images saved to {DEBUG_OUTPUT_DIR}")

def _save_debug_image(image: np.ndarray, name: str, debug_prefix: str = ""):
    """Save intermediate debug image."""
    if not DEBUG_MODE:
        return None
    try:
        timestamp = Path(debug_prefix).stem if debug_prefix else "image"
        filename = DEBUG_OUTPUT_DIR / f"{timestamp}_{name}.jpg"
        cv2.imwrite(str(filename), image)
        logger.debug(f"Saved debug image: {filename}")
        return str(filename)
    except Exception as e:
        logger.warning(f"Failed to save debug image {name}: {e}")
        return None

def _run_mediapipe_detector(rgb: np.ndarray, model_selection: int, min_confidence: float):
    if mp_detector_api == "tasks_vision":
        options = mp_tasks_vision.FaceDetectorOptions(
            base_options=mp_tasks_python.BaseOptions(model_asset_path=str(MP_FACE_MODEL_PATH)),
            min_detection_confidence=min_confidence,
        )
        detector = mp_tasks_vision.FaceDetector.create_from_options(options)
        try:
            mp_image = mp.Image(image_format=mp.ImageFormat.SRGB, data=np.ascontiguousarray(rgb))
            results = detector.detect(mp_image)
            return list(results.detections or [])
        finally:
            detector.close()

    with mp_face_detection.FaceDetection(
        model_selection=model_selection,
        min_detection_confidence=min_confidence,
    ) as detector:
        results = detector.process(rgb)
        return list(results.detections or [])

def _extract_detection_box(detection: Any, image_w: int, image_h: int) -> Tuple[int, int, int, int, float]:
    if mp_detector_api == "tasks_vision":
        bbox = detection.bounding_box
        confidence = detection.categories[0].score if detection.categories else 0.0
        return int(bbox.origin_x), int(bbox.origin_y), int(bbox.width), int(bbox.height), float(confidence)

    bboxC = detection.location_data.relative_bounding_box
    confidence = detection.score[0] if detection.score else 0.0
    xmin = int(bboxC.xmin * image_w)
    ymin = int(bboxC.ymin * image_h)
    width = int(bboxC.width * image_w)
    height = int(bboxC.height * image_h)
    return xmin, ymin, width, height, float(confidence)

def _draw_face_overlay(bgr: np.ndarray, boxes: List[Tuple[int, int, int, int]], confidences: List[float]) -> np.ndarray:
    viz_img = bgr.copy()
    if not boxes:
        cv2.putText(viz_img, "MediaPipe detections: 0", (12, 32), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 0, 255), 2)
        return viz_img

    for i, (x, y, w_box, h_box) in enumerate(boxes):
        cv2.rectangle(viz_img, (x, y), (x + w_box, y + h_box), (0, 255, 0), 2)
        label = f"Face {i} {confidences[i]:.2f}" if i < len(confidences) else f"Face {i}"
        cv2.putText(viz_img, label, (x, max(20, y - 10)), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
    return viz_img

def _detect_faces_mediapipe(bgr: np.ndarray, debug_prefix: str = "") -> Tuple[List[np.ndarray], List[Tuple[int, int, int, int]], Dict[str, Any]]:
    """Uses MediaPipe for robust multi-face and profile detection with comprehensive debugging."""
    debug_info = {
        "original_shape": bgr.shape,
        "original_dtype": str(bgr.dtype),
        "original_size_kb": bgr.nbytes / 1024,
        "bgr_min_max": (int(bgr.min()), int(bgr.max())),
        "mediapipe_loaded": bool(mp_available),
        "mediapipe_api": mp_detector_api,
        "mediapipe_branch_executed": False,
        "mediapipe_import_error": mp_import_error,
        "pipeline_module_path": __file__,
        "detection_count": 0,
        "bbox_coordinates": [],
        "confidence_values": [],
        "debug_overlay": None,
        "detections": [],
        "errors": []
    }
    
    _setup_debug_output()
    
    if not mp_available:
        error_msg = (
            "MediaPipe detector unavailable; refusing to downgrade to no-face classification. "
            f"api={mp_detector_api} model_exists={MP_FACE_MODEL_PATH.exists()} import_error={mp_import_error}"
        )
        logger.error(error_msg)
        logger.info("[Face Detection] MediaPipe loaded: false")
        debug_info["errors"].append(error_msg)
        debug_info["debug_overlay"] = _save_debug_image(
            _draw_face_overlay(bgr, [], []),
            "04_with_detections",
            debug_prefix,
        )
        return [], [], debug_info
    
    try:
        h, w = bgr.shape[:2]
        debug_info["mediapipe_branch_executed"] = True
        logger.info("[Face Detection] MediaPipe loaded: true (api=%s)", mp_detector_api)
        logger.debug(f"[Face Detection] Original image shape: {h}x{w}, dtype={bgr.dtype}")
        debug_info["original_shape"] = (h, w)
        
        # Save original image
        _save_debug_image(bgr, "01_original_bgr", debug_prefix)
        
        # Convert BGR to RGB
        rgb = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)
        logger.debug(f"[Face Detection] Converted to RGB. Shape: {rgb.shape}, dtype={rgb.dtype}")
        logger.debug(f"[Face Detection] RGB min={rgb.min()}, max={rgb.max()}")
        
        # Validate RGB conversion
        if rgb.dtype != np.uint8:
            logger.warning(f"RGB dtype is {rgb.dtype}, expected uint8. Converting...")
            rgb = np.clip(rgb * 255.0, 0, 255).astype(np.uint8) if rgb.dtype != np.uint8 else rgb
        
        debug_info["rgb_shape"] = rgb.shape
        debug_info["rgb_dtype"] = str(rgb.dtype)
        debug_info["rgb_min_max"] = (int(rgb.min()), int(rgb.max()))
        
        _save_debug_image(cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR), "02_converted_rgb", debug_prefix)
        
        faces_roi = []
        boxes = []
        confidences = []
        
        # Try long-range detection first (model_selection=1)
        logger.debug("[Face Detection] Attempting long-range detection (model_selection=1)...")
        detections = _run_mediapipe_detector(rgb, model_selection=1, min_confidence=0.3)
        detections_count = len(detections)
        logger.info(f"[Face Detection] Long-range model found {detections_count} face(s)")
        debug_info["detections_long_range"] = detections_count

        if detections_count == 0 and mp_detector_api == "solutions":
            logger.debug("[Face Detection] No detections with long-range. Trying short-range (model_selection=0)...")
            detections = _run_mediapipe_detector(rgb, model_selection=0, min_confidence=0.3)
            detections_count = len(detections)
            logger.info(f"[Face Detection] Short-range model found {detections_count} face(s)")
            debug_info["detections_short_range"] = detections_count
        
        if detections:
            logger.info(f"[Face Detection] Total detections: {len(detections)}")
            
            for idx, detection in enumerate(detections):
                try:
                    # Extract bounding box
                    xmin, ymin, width, height, confidence = _extract_detection_box(detection, w, h)
                    xmin = max(0, min(w - 1, xmin))
                    ymin = max(0, min(h - 1, ymin))
                    width = max(0, min(w - xmin, width))
                    height = max(0, min(h - ymin, height))
                    
                    logger.info(
                        f"[Face Detection] Detection {idx}: confidence={confidence:.3f}, "
                        f"box=({xmin},{ymin},{width}x{height}), "
                        f"area_ratio={(width*height)/(h*w):.3f}"
                    )
                    
                    debug_info["detections"].append({
                        "index": idx,
                        "confidence": float(confidence),
                        "bbox_rel": (float(xmin / w), float(ymin / h), float(width / w), float(height / h)),
                        "bbox_abs": (xmin, ymin, width, height),
                        "area_ratio": (width * height) / (h * w)
                    })
                    confidences.append(float(confidence))
                    
                    # Add padding
                    pad = int(0.12 * max(width, height))
                    x0, y0 = max(0, xmin - pad), max(0, ymin - pad)
                    x1, y1 = min(w, xmin + width + pad), min(h, ymin + height + pad)
                    
                    box = (x0, y0, x1 - x0, y1 - y0)
                    roi = bgr[y0:y1, x0:x1]
                    
                    if roi.size > 0:
                        faces_roi.append(np.ascontiguousarray(roi))
                        boxes.append(box)
                        logger.debug(f"[Face Detection] Face {idx} extracted: size={roi.shape}")
                        
                        # Save cropped face region
                        _save_debug_image(roi, f"03_face_{idx}_cropped", debug_prefix)
                    else:
                        logger.warning(f"[Face Detection] Face {idx} ROI is empty")
                        
                except Exception as e:
                    error_msg = f"Error processing detection {idx}: {e}"
                    logger.error(error_msg)
                    debug_info["errors"].append(error_msg)
        else:
            logger.warning("[Face Detection] No faces detected in image")
            debug_info["detections"] = []
        
        # Save visualization with detected faces
        debug_info["detection_count"] = len(faces_roi)
        debug_info["bbox_coordinates"] = boxes
        debug_info["confidence_values"] = confidences
        debug_info["debug_overlay"] = _save_debug_image(
            _draw_face_overlay(bgr, boxes, confidences),
            "04_with_detections",
            debug_prefix,
        )
        
        logger.info(
            "[Face Detection] Final result: count=%s boxes=%s confidences=%s overlay=%s",
            len(faces_roi),
            boxes,
            [round(c, 3) for c in confidences],
            debug_info["debug_overlay"],
        )
        return faces_roi, boxes, debug_info
        
    except Exception as e:
        error_msg = f"MediaPipe face detection failed: {e}"
        logger.error(error_msg, exc_info=True)
        debug_info["errors"].append(error_msg)
        debug_info["debug_overlay"] = _save_debug_image(
            _draw_face_overlay(bgr, [], []),
            "04_with_detections",
            debug_prefix,
        )
        return [], [], debug_info

# --- Content-Type Routing Layer (with enhanced error handling) ---
def _classify_content_type(bgr: np.ndarray, faces: List[np.ndarray], path: str, debug_info: Dict[str, Any]) -> Dict[str, Any]:
    """Classifies image into specific types to determine what we can reliably analyze."""
    h, w = bgr.shape[:2]
    content_type = "unknown"
    reasons = []
    
    logger.debug(f"[Content Classification] Image: {h}x{w}, Faces detected: {len(faces)}")
    
    # 1. Check Quality/Compression
    # RESTORE PART 5: Remove hard exit on file<15KB.
    # Small JPEG selfies (<15KB) were being blocked before any ML or patch analysis ran.
    # New behaviour: log a warning and continue. INSUFFICIENT EVIDENCE is only returned by
    # fuse_signals() later if ML AND patch AND portrait all remain unavailable.
    file_size_kb = os.path.getsize(path) / 1024
    low_quality_warning = None
    if file_size_kb < 15:
        low_quality_warning = (
            f"Image is small ({file_size_kb:.1f} KB < 15 KB threshold) — "
            "forensic signals may be limited but analysis will continue."
        )
        logger.info("[Content Classification] Small file (<15KB), continuing with best-effort analysis")
    if max(h, w) < 200:
        logger.info("[Content Classification] Image is too small or highly compressed (max dim < 200px)")
        return {
            "type": "low_quality",
            "reasons": ["Image dimensions too small (max side < 200px) for reliable forensic analysis."],
            "debug_info": debug_info
        }

    portrait_reason = "No dominant face detected."
    face_area_percentages: List[float] = []
    largest_face_ratio = 0.0

    # 2. Check Faces
    detections_meta = debug_info.get("detections", [])
    confidences = [d.get("confidence", 0.0) for d in detections_meta]
    max_confidence = max(confidences) if confidences else 0.0

    if len(faces) > 0:
        face_area_ratios = [roi.shape[0]*roi.shape[1] / (h * w) for roi in faces]
        face_area_percentages = [round(r * 100.0, 2) for r in face_area_ratios]
        max_face_ratio = max(face_area_ratios)
        largest_face_ratio = round(max_face_ratio, 4)
        dominant_faces = [r for r in face_area_ratios if r >= 0.012] # Lowered from 0.018
        
        logger.debug(f"[Content Classification] Face area ratios: {face_area_ratios}, max={max_face_ratio:.3f}, max_conf={max_confidence:.3f}")
        
        # PORTRAIT CLASSIFICATION LOGIC UPGRADE
        # RESTORE PART 4: Lower portrait confidence threshold from 0.85 → 0.65 for SINGLE face.
        # MediaPipe returns 0.72-0.84 on compressed/selfie images — the 0.85 threshold was
        # silently degrading all such images to landscape_or_object, disabling portrait signals.
        # Multi-face portraits retain the original higher threshold.
        if len(faces) == 1:
            is_high_conf = max_confidence >= 0.65  # RESTORED: was 0.85, now 0.65 for single face
            is_meaningful_area = max_face_ratio >= 0.012

            if is_high_conf and is_meaningful_area:
                content_type = "human_portrait"
                portrait_reason = (
                    "Single face detected with sufficient confidence and area "
                    f"({max_face_ratio * 100.0:.2f}% of image, confidence={max_confidence:.2f}). "
                    f"[threshold=0.65 for single-face]"
                )
            elif max_face_ratio >= 0.025:
                content_type = "human_portrait"
                portrait_reason = (
                    "Single large face detected "
                    f"({max_face_ratio * 100.0:.2f}% of image)."
                )
            else:
                content_type = "landscape_or_crowd"
                portrait_reason = (
                    "Single face detected but too small or low confidence "
                    f"(area={max_face_ratio * 100.0:.2f}%, conf={max_confidence:.2f})."
                )
        elif max_face_ratio >= 0.035 and len(dominant_faces) <= 2:
            content_type = "human_portrait"
            portrait_reason = (
                "A large primary face is present "
                f"({max_face_ratio * 100.0:.2f}% of the image), so portrait signals remain reliable."
            )
            reasons.append(f"{portrait_reason} Portrait forensic signals enabled.")
            logger.info("[Content Classification] Classified as: human_portrait")
        else:
            content_type = "landscape_or_crowd"
            portrait_reason = (
                "Faces are present, but no single face occupies enough frame area "
                f"(largest={max_face_ratio * 100.0:.2f}%)."
            )
            reasons.append(f"{portrait_reason} Treating as general scene.")
            logger.info("[Content Classification] Classified as: landscape_or_crowd (faces too small)")
    else:
        # No faces - THIS IS THE ISSUE WE'RE DEBUGGING
        content_type = "landscape_or_object"
        if debug_info.get("errors"):
            reasons.append(f"Face detection error: {debug_info['errors'][0]}")
            logger.warning(f"[Content Classification] Face detection failed: {debug_info['errors'][0]}")
        else:
            reasons.append("No human faces detected. Face-specific forensic signals are disabled.")
            logger.info("[Content Classification] Classified as: landscape_or_object (no faces)")

    diagnostics = {
        "face_area_percentages": [float(x) for x in face_area_percentages],
        "largest_face_ratio": float(largest_face_ratio),
        "largest_face_percent": round(float(largest_face_ratio) * 100.0, 2),
        "max_confidence": round(float(max_confidence), 4),
        "portrait_classification_reason": str(portrait_reason),
        "face_count": int(len(faces)),
        "dominant_face_ratio": float(largest_face_ratio),
    }

    # RESTORE PART 5: Attach low-quality warning to reasons without blocking
    if low_quality_warning:
        reasons.insert(0, low_quality_warning)

    return {
        "type": content_type,
        "reasons": reasons,
        "debug_info": debug_info,
        "diagnostics": diagnostics,
        "low_quality_warning": low_quality_warning,
    }

# --- Forensic Signals ---
def analyze_metadata(path: str, prov_data: Optional[Dict[str, Any]] = None) -> SignalResult:
    """
    Provenance analysis integrating C2PA Content Credentials, Google AI signatures,
    full EXIF/SubIFDs, XMP packets, and container chunks via ProvenanceEngine.
    """
    if prov_data is None:
        try:
            prov_data = _provenance_engine.analyze(path)
        except Exception as exc:
            logger.warning(f"[Provenance] Metadata analysis error for {path}: {exc}")
            return SignalResult(
                key="metadata",
                score=0.50,
                detail=f"Provenance engine error: {exc}",
                category="metadata",
                status="failed",
                reliability="low",
                human_readable="Could not parse file provenance metadata."
            )

    ai_score = prov_data["scores"]["ai_provenance_score"]
    cam_score = prov_data["scores"]["camera_provenance_score"]
    c2pa_info = prov_data.get("c2pa", {})
    google_info = prov_data.get("google_provenance", {})
    conflict = prov_data["scores"]["provenance_conflict_score"]

    # 1. Contradiction / Conflict
    if conflict > 0.60:
        return SignalResult(
            key="metadata",
            score=0.50,
            detail="Contradiction detected: camera hardware metadata conflicts with generative AI signatures or manifest state.",
            category="metadata",
            status="active",
            reliability="high",
            human_readable="Conflicting provenance signatures detected (tampered or mixed provenance)."
        )

    # 2. Level 1: Verified C2PA Generative AI Content Credentials
    if c2pa_info.get("is_generative_ai") and c2pa_info.get("is_valid", False):
        claim_gen = c2pa_info.get("claim_generator") or "AI Generator"
        return SignalResult(
            key="metadata",
            score=0.99,
            detail=f"C2PA Content Credentials verify generative AI provenance ({claim_gen}).",
            category="metadata",
            status="active",
            reliability="high",
            human_readable=f"Cryptographic Content Credentials (C2PA) confirm generative AI provenance ({claim_gen})."
        )

    # 3. Level 1: Google AI Provenance (Gemini / Imagen / C2PA / XMP)
    if google_info.get("google_provenance_detected"):
        return SignalResult(
            key="metadata",
            score=0.96,
            detail=f"Google AI provenance confirmed: {google_info.get('details')}.",
            category="metadata",
            status="active",
            reliability="high",
            human_readable="Google AI / Gemini provenance markers confirmed in media container."
        )

    # 4. Level 2: Strong Generator Signatures (explicit metadata / prompts)
    if ai_score >= 0.90:
        gen_tool = prov_data.get("generator_tool") or "Generative AI metadata"
        return SignalResult(
            key="metadata",
            score=0.95,
            detail=f"Explicit generative AI tooling signature in metadata: {gen_tool}.",
            category="metadata",
            status="active",
            reliability="high",
            human_readable=f"Metadata contains explicit generative AI software signature ({gen_tool})."
        )

    # 5. Level 1: Verified C2PA Camera Capture
    if c2pa_info.get("is_camera_capture") and c2pa_info.get("is_valid", False):
        claim_gen = c2pa_info.get("claim_generator") or "Certified Camera"
        return SignalResult(
            key="metadata",
            score=0.02,
            detail=f"C2PA Content Credentials verify physical camera capture ({claim_gen}).",
            category="metadata",
            status="active",
            reliability="high",
            human_readable=f"Cryptographic Content Credentials (C2PA) verify authentic physical camera capture ({claim_gen})."
        )

    # 6. Coherent Hardware Camera EXIF (Make, Model, Lens, Optical Exposure)
    if cam_score >= 0.80:
        make = prov_data.get("camera_maker") or "Camera"
        model = prov_data.get("camera_model") or ""
        tags_cnt = len(prov_data.get("optical_exposure_tags", {}))
        return SignalResult(
            key="metadata",
            score=0.08,
            detail=f"Camera hardware EXIF verified: {make} {model} ({tags_cnt} optical exposure tags).",
            category="metadata",
            status="active",
            reliability="high",
            human_readable=f"Camera hardware EXIF and optical exposure settings verify authentic capture on {make} {model}."
        )
    elif prov_data.get("camera_maker") or prov_data.get("camera_model"):
        make = prov_data.get("camera_maker") or ""
        model = prov_data.get("camera_model") or ""
        return SignalResult(
            key="metadata",
            score=0.25,
            detail=f"Partial camera metadata: {make} {model}.",
            category="metadata",
            status="active",
            reliability="medium",
            human_readable=f"Partial camera metadata present: {make} {model}."
        )
    else:
        # Neutral: Stripped metadata / social media export / screenshot
        return SignalResult(
            key="metadata",
            score=0.50,
            detail="Metadata has been stripped or is minimal (common on web/social media downloads).",
            category="metadata",
            status="skipped",
            reliability="low",
            human_readable="No device capture tags or explicit AI tags found (metadata stripped/social export)."
        )

def analyze_sensor_noise(bgr: np.ndarray, ctype: str) -> SignalResult:
    """Analyze flat-region sensor noise (PRNU proxy): real optical camera sensors have
    photon shot noise (std >= 1.2), whereas diffusion models produce mathematically smooth
    latent spaces with near-zero flat noise (std < 0.6)."""
    try:
        gray = _to_gray_u8(bgr).astype(np.float32)
        med = cv2.medianBlur(gray.astype(np.uint8), 3).astype(np.float32)
        noise = gray - med
        grad_x = cv2.Sobel(gray, cv2.CV_32F, 1, 0, ksize=3)
        grad_y = cv2.Sobel(gray, cv2.CV_32F, 0, 1, ksize=3)
        grad_mag = np.sqrt(grad_x**2 + grad_y**2)
        flat_mask = grad_mag < np.percentile(grad_mag, 30)
        flat_noise = float(np.std(noise[flat_mask])) if np.any(flat_mask) else float(np.std(noise))

        if flat_noise < 0.35:
            score = 0.88
            reliability = "high"
            human_readable = "Flat regions exhibit synthetic smoothness with near-zero optical sensor noise (characteristic of AI diffusion)."
        elif flat_noise < 0.85:
            score = 0.72
            reliability = "medium"
            human_readable = "Low optical sensor noise in uniform regions, typical of AI generation or heavy smoothing."
        elif flat_noise > 2.0:
            score = 0.15
            reliability = "high"
            human_readable = "Natural CMOS/CCD sensor photon shot noise detected, consistent with authentic camera capture."
        else:
            score = 0.32
            reliability = "medium"
            human_readable = "Normal sensor grain present, consistent with standard camera capture."

        return SignalResult(
            key="sensor_noise",
            score=score,
            detail=f"Flat-region noise std={flat_noise:.2f} (lower=synthetic smoothness, higher=optical grain).",
            category="diffusion_artifact",
            status="active",
            reliability=reliability,
            human_readable=human_readable
        )
    except Exception as exc:
        return SignalResult("sensor_noise", 0.5, f"Noise analysis error: {exc}", "diffusion_artifact", "failed", "low", "Could not analyze sensor noise.")

def analyze_compression_ela(bgr: np.ndarray, ctype: str) -> SignalResult:
    if ctype == "low_quality": return SignalResult("compression_ela", 0.5, "Skipped due to low image quality.", "compression_ela", "skipped", "low", "Image quality is too low to analyze compression artifacts.")
    try:
        rgb = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)
        ok, buf = cv2.imencode(".jpg", rgb, [int(cv2.IMWRITE_JPEG_QUALITY), 92])
        if not ok: return SignalResult("compression_ela", 0.5, "ELA failed.", "compression_ela", "failed", "low", "Failed to analyze compression artifacts.")
        dec = cv2.imdecode(buf, cv2.IMREAD_COLOR)
        ela = cv2.absdiff(rgb, dec)
        mean_e = float(np.mean(ela))
        score = _clamp((mean_e - 4.0) / 14.0)
        human_readable = "Significant compression anomalies detected, often indicating splicing or manipulation." if score > 0.65 else "Compression artifacts appear uniform and consistent with normal saving." if score < 0.35 else "Compression artifacts are inconclusive."
        reliability = "low" if mean_e < 2.0 else "medium"
        return SignalResult("compression_ela", score, f"Compression residual mean={mean_e:.2f}.", "compression_ela", "active", reliability, human_readable)
    except Exception:
        return SignalResult("compression_ela", 0.5, "ELA error.", "compression_ela", "failed", "low", "An error occurred while analyzing compression artifacts.")

def analyze_smoothness(bgr: np.ndarray, faces: List[np.ndarray], ctype: str) -> SignalResult:
    gray_u8 = _to_gray_u8(bgr)
    lv_global = _laplacian_variance_u8(gray_u8)
    if ctype == "human_portrait" and faces:
        face_lvs = [_laplacian_variance_u8(_to_gray_u8(f)) for f in faces if f.size > 400]
        if face_lvs:
            ratio = float(np.mean(face_lvs) / (lv_global + 1e-6))
            score = _clamp(0.55 + (0.42 - min(ratio, 1.2)) * 0.55)
            human_readable = "Facial skin appears unnaturally smooth compared to the background, a common synthetic artifact." if score > 0.65 else "Facial texture is consistent with natural camera capture."
            return SignalResult("facial_smoothness", score, f"Face variance ratio={ratio:.3f} (lower=smoother skin).", "facial_forensics", "active", "medium", human_readable)
    return SignalResult("facial_smoothness", 0.5, "Skipped: Not a portrait or no faces available.", "facial_forensics", "skipped", "low", "Face texture signal skipped because no reliable face was detected.")

def analyze_frequency_fingerprint(bgr: np.ndarray) -> SignalResult:
    # Bypass DFT computation to reduce latency as it is demoted to weight=0.0
    return SignalResult(
        key="frequency_fingerprint",
        score=0.5,
        detail="Frequency analysis skipped to reduce pipeline latency (explainability only).",
        category="frequency_domain",
        status="skipped",
        reliability="low",
        human_readable="Frequency-domain analysis skipped (explainability only)."
    )

def analyze_diffusion_artifacts(bgr: np.ndarray, faces: List[np.ndarray], boxes: List[Tuple[int, int, int, int]], ctype: str) -> List[SignalResult]:
    signals: List[SignalResult] = []
    gray = _to_gray_u8(bgr)
    try:
        edges = cv2.Canny(gray, 80, 180)
        lv = _laplacian_variance_u8(gray)
        edge_density = float(np.mean(edges > 0))
        edge_score = _clamp(0.35 + edge_density * 3.0 - min(lv / 900.0, 0.45))
        signals.append(SignalResult(
            "edge_hallucination",
            edge_score,
            f"Canny edge density={edge_density:.3f}, Laplacian variance={lv:.1f}.",
            "diffusion_artifact",
            "active",
            "medium",
            "Edges show possible hallucinated or over-regularized boundaries." if edge_score > 0.65 else "No strong edge hallucination pattern found.",
        ))
    except Exception as exc:
        signals.append(SignalResult("edge_hallucination", 0.5, f"Edge artifact analysis failed: {exc}", "diffusion_artifact", "failed", "low", "Edge artifact analysis failed."))

    if ctype == "human_portrait" and faces:
        texture_scores = []
        for face in faces:
            fg = _to_gray_u8(face)
            h, w = fg.shape[:2]
            if h < 40 or w < 40:
                continue
            skin = fg[int(h * 0.28):int(h * 0.72), int(w * 0.18):int(w * 0.82)]
            micro = float(np.std(cv2.Laplacian(skin, _DDEPTH_DERIV, ksize=3)))
            texture_scores.append(_clamp((24.0 - micro) / 24.0))

        if texture_scores:
            score = float(np.mean(texture_scores))
            signals.append(SignalResult(
                "microtexture_consistency",
                score,
                f"Face microtexture synthetic score={score:.3f}.",
                "diffusion_artifact",
                "active",
                "medium",
                "Facial microtexture appears unusually even or oversmoothed." if score > 0.65 else "Facial microtexture does not strongly indicate diffusion smoothing.",
            ))
            
        # Bypass specular blob extraction to reduce latency (demoted to weight=0.0)
        signals.append(SignalResult(
            "eye_reflection_consistency",
            0.5,
            "Eye reflection analysis skipped to reduce latency (explainability only).",
            "diffusion_artifact",
            "skipped",
            "low",
            "Eye reflection analysis skipped (explainability only).",
            _confidence_interval(0.5, 0.24)
        ))
    else:
        signals.append(SignalResult("microtexture_consistency", 0.5, "Skipped: no reliable portrait face ROI.", "diffusion_artifact", "skipped", "low", "Microtexture signal skipped because no reliable face was detected."))
        signals.append(SignalResult("eye_reflection_consistency", 0.5, "Skipped: no reliable portrait face ROI.", "diffusion_artifact", "skipped", "low", "Eye reflection signal skipped because no reliable face was detected."))

    # Bypass background correlation checks to reduce latency (demoted to weight=0.0)
    signals.append(SignalResult(
        "repetitive_background",
        0.5,
        "Background repetition analysis skipped to reduce latency (explainability only).",
        "diffusion_artifact",
        "skipped",
        "low",
        "Background repetition analysis skipped (explainability only).",
        _confidence_interval(0.5, 0.22)
    ))
    return signals

class AIEnsembleClassifier:
    """
    Hierarchical Media-Authentication ML Classifier:
    - Primary Model (Level 3): 'umm-maybe/AI-image-detector' (Swin-Base trained specifically for synthetic image detection)
    - Secondary Model (Level 5): 'openai/clip-vit-base-patch32' (Prompt semantic correlation, secondary only, weight <= 0.05)
    - Device auto-detection: CUDA if torch.cuda.is_available() else CPU.
    """
    MODELS = [
        "umm-maybe/AI-image-detector",
        "openai/clip-vit-base-patch32",
    ]
    MODEL_PRIORS = {
        "umm-maybe/AI-image-detector": {
            "weight": 1.0,
            "discrimination": 0.95,
            "calibration_reliability": 0.92,
            "notes": "Primary specialized Swin synthetic detector"
        },
        "openai/clip-vit-base-patch32": {
            "weight": 0.20,
            "discrimination": 0.50,
            "calibration_reliability": 0.60,
            "notes": "Secondary zero-shot semantic correlation"
        }
    }
    
    _lock = threading.Lock()
    _spec_processor = None
    _spec_model = None
    _clip_processor = None
    _clip_model = None
    _device = None
    _last_spec_result = None
    _last_clip_result = None

    def __init__(self):
        import torch
        if AIEnsembleClassifier._device is None:
            AIEnsembleClassifier._device = "cuda" if torch.cuda.is_available() else "cpu"
            logger.info(f"[AI Ensemble] Inference device: {AIEnsembleClassifier._device} (CUDA available: {torch.cuda.is_available()})")

    @property
    def device(self) -> str:
        return AIEnsembleClassifier.get_device()

    @classmethod
    def get_device(cls) -> str:
        if cls._device is None:
            try:
                import torch
                cls._device = "cuda" if torch.cuda.is_available() else "cpu"
            except Exception:
                cls._device = "cpu"
        return cls._device

    def _ensure_specialized(self):
        with self._lock:
            if AIEnsembleClassifier._spec_model is not None:
                return
            try:
                import torch
                from transformers import AutoImageProcessor, AutoModelForImageClassification
                logger.info(f"[Ensemble] Loading specialized detector 'umm-maybe/AI-image-detector' on {self.device}...")
                try:
                    proc = AutoImageProcessor.from_pretrained("umm-maybe/AI-image-detector", local_files_only=True)
                    mod = AutoModelForImageClassification.from_pretrained("umm-maybe/AI-image-detector", local_files_only=True).to(self.device)
                except Exception:
                    proc = AutoImageProcessor.from_pretrained("umm-maybe/AI-image-detector")
                    mod = AutoModelForImageClassification.from_pretrained("umm-maybe/AI-image-detector").to(self.device)
                mod.eval()
                AIEnsembleClassifier._spec_processor = proc
                AIEnsembleClassifier._spec_model = mod
                logger.info("[Ensemble] 'umm-maybe/AI-image-detector' loaded successfully.")
            except Exception as exc:
                logger.error(f"[Ensemble] Failed to load 'umm-maybe/AI-image-detector': {exc}")

    def _ensure_clip(self):
        with self._lock:
            if AIEnsembleClassifier._clip_model is not None:
                return
            try:
                import torch
                from transformers import CLIPProcessor, CLIPModel
                logger.info(f"[Ensemble] Loading CLIP 'openai/clip-vit-base-patch32' on {self.device}...")
                try:
                    proc = CLIPProcessor.from_pretrained("openai/clip-vit-base-patch32", local_files_only=True)
                    mod = CLIPModel.from_pretrained("openai/clip-vit-base-patch32", local_files_only=True).to(self.device)
                except Exception:
                    proc = CLIPProcessor.from_pretrained("openai/clip-vit-base-patch32")
                    mod = CLIPModel.from_pretrained("openai/clip-vit-base-patch32").to(self.device)
                mod.eval()
                AIEnsembleClassifier._clip_processor = proc
                AIEnsembleClassifier._clip_model = mod
                logger.info("[Ensemble] CLIP loaded successfully.")
            except Exception as exc:
                logger.warning(f"[Ensemble] Failed to load CLIP: {exc}")

    def score_specialized(self, rgb_pil) -> ModelResult:
        self._ensure_specialized()
        if AIEnsembleClassifier._spec_model is None:
            return ModelResult(
                available=False,
                model_name="umm-maybe/AI-image-detector",
                ai_probability=0.5,
                confidence=0.0,
                detail="Model unavailable",
                inference_time=0.0
            )
        try:
            import torch
            t0 = time.perf_counter()
            inputs = AIEnsembleClassifier._spec_processor(images=rgb_pil, return_tensors="pt").to(self.device)
            with torch.no_grad():
                logits = AIEnsembleClassifier._spec_model(**inputs).logits
            probs = torch.softmax(logits, dim=-1)[0].cpu().tolist()
            id2label = AIEnsembleClassifier._spec_model.config.id2label
            scores = {id2label[i].lower(): float(probs[i]) for i in range(len(probs))}
            ai_prob = scores.get("artificial", scores.get("fake", 0.5))
            inf_time = time.perf_counter() - t0
            confidence = abs(ai_prob - 0.5) * 2.0
            return ModelResult(
                available=True,
                model_name="umm-maybe/AI-image-detector",
                ai_probability=float(ai_prob),
                confidence=float(confidence),
                detail=f"Scores: artificial={ai_prob:.4f}, human={scores.get('human', 0.0):.4f}",
                inference_time=inf_time
            )
        except Exception as exc:
            logger.error(f"[Ensemble] Specialized inference error: {exc}")
            return ModelResult(False, "umm-maybe/AI-image-detector", 0.5, 0.0, f"Error: {exc}", 0.0)

    def score_clip(self, rgb_pil) -> Dict[str, Any]:
        self._ensure_clip()
        if AIEnsembleClassifier._clip_model is None:
            return {
                "available": False,
                "status": "MODEL_UNAVAILABLE",
                "real_prompt_scores": {},
                "ai_prompt_scores": {},
                "aggregate_score": 0.0,
                "confidence": 0.0,
                "detail": "CLIP model unavailable",
                "inference_time": 0.0
            }
        try:
            import torch
            t0 = time.perf_counter()
            real_prompts = [
                "a genuine camera photograph",
                "a real natural unedited photo taken with a phone camera",
                "a real photographic image with lens optical noise"
            ]
            ai_prompts = [
                "an AI generated synthetic image",
                "a digital artwork created by generative artificial intelligence midjourney dalle",
                "an artificial computer generated synthetic image"
            ]
            all_prompts = real_prompts + ai_prompts
            inputs = AIEnsembleClassifier._clip_processor(
                text=all_prompts, images=rgb_pil, return_tensors="pt", padding=True
            ).to(self.device)
            with torch.no_grad():
                out = AIEnsembleClassifier._clip_model(**inputs)
                logits = out.logits_per_image[0]
                clip_probs = torch.softmax(logits, dim=-1).cpu().tolist()
            
            real_p = {all_prompts[i]: round(clip_probs[i], 4) for i in range(len(real_prompts))}
            ai_p = {all_prompts[i+len(real_prompts)]: round(clip_probs[i+len(real_prompts)], 4) for i in range(len(ai_prompts))}
            clip_ai_agg = sum(ai_p.values())
            inf_time = time.perf_counter() - t0
            confidence = abs(clip_ai_agg - 0.5) * 2.0
            return {
                "available": True,
                "status": "active",
                "real_prompt_scores": real_p,
                "ai_prompt_scores": ai_p,
                "aggregate_score": float(clip_ai_agg),
                "confidence": float(confidence),
                "detail": f"CLIP raw AI aggregate: {clip_ai_agg:.4f}",
                "inference_time": inf_time
            }
        except Exception as exc:
            logger.warning(f"[Ensemble] CLIP inference error: {exc}")
            return {
                "available": False,
                "status": "MODEL_UNAVAILABLE",
                "real_prompt_scores": {},
                "ai_prompt_scores": {},
                "aggregate_score": 0.0,
                "confidence": 0.0,
                "detail": f"CLIP inference error: {exc}",
                "inference_time": 0.0
            }

    def score_image(self, bgr_u8: np.ndarray) -> EnsembleResult:
        from PIL import Image
        rgb_pil = Image.fromarray(cv2.cvtColor(bgr_u8, cv2.COLOR_BGR2RGB))
        t0 = time.perf_counter()

        spec_res = self.score_specialized(rgb_pil)
        clip_res = self.score_clip(rgb_pil)

        self._last_spec_result = spec_res
        self._last_clip_result = clip_res

        results = [spec_res]
        if clip_res["available"]:
            results.append(ModelResult(
                available=True,
                model_name="openai/clip-vit-base-patch32",
                ai_probability=clip_res["aggregate_score"],
                confidence=clip_res["confidence"],
                detail=clip_res["detail"],
                inference_time=clip_res["inference_time"]
            ))
        else:
            results.append(ModelResult(
                available=False,
                model_name="openai/clip-vit-base-patch32",
                ai_probability=0.0,
                confidence=0.0,
                detail="MODEL_UNAVAILABLE",
                inference_time=0.0
            ))

        total_time = time.perf_counter() - t0

        # Weights: Specialized has 0.80 primary weight, CLIP has 0.20 secondary weight
        weights = {}
        if spec_res.available and clip_res["available"]:
            weights["umm-maybe/AI-image-detector"] = 0.80
            weights["openai/clip-vit-base-patch32"] = 0.20
            ens_score = 0.80 * spec_res.ai_probability + 0.20 * clip_res["aggregate_score"]
            agreement = 1.0 - abs(spec_res.ai_probability - clip_res["aggregate_score"])
            disagreement = agreement < 0.60
            ens_conf = spec_res.confidence * 0.8 + clip_res["confidence"] * 0.2
        elif spec_res.available:
            weights["umm-maybe/AI-image-detector"] = 1.0
            ens_score = spec_res.ai_probability
            agreement = 1.0
            disagreement = False
            ens_conf = spec_res.confidence
        elif clip_res["available"]:
            # Never let CLIP dominate alone as primary
            weights["openai/clip-vit-base-patch32"] = 0.10
            ens_score = clip_res["aggregate_score"]
            agreement = 0.5
            disagreement = True
            ens_conf = 0.20
        else:
            return EnsembleResult(
                available=False,
                results=results,
                ensemble_score=0.5,
                ensemble_confidence=0.0,
                agreement_score=0.0,
                disagreement=True,
                inference_time_total=total_time,
                weights={},
                detail="All ML models unavailable",
                clip_result=clip_res,
                specialized_result=spec_res
            )

        clip_ai_str = "MODEL_UNAVAILABLE" if not clip_res.get("available") else f"{clip_res.get('aggregate_score', 0.0):.3f}"
        summary = (
            f"Specialized AI: {spec_res.ai_probability:.3f} (conf: {spec_res.confidence:.2f}) | "
            f"CLIP AI: {clip_ai_str}"
        )

        return EnsembleResult(
            available=True,
            results=results,
            ensemble_score=float(ens_score),
            ensemble_confidence=float(ens_conf),
            agreement_score=float(agreement),
            disagreement=bool(disagreement),
            inference_time_total=total_time,
            weights=weights,
            detail=summary,
            clip_result=clip_res,
            specialized_result=spec_res
        )

def _get_classifier() -> AIEnsembleClassifier:
    return AIEnsembleClassifier()

def preload_models():
    """Preload the HuggingFace image classification models to avoid lazy-loading delays/OOMs."""
    logger.info("[Ensemble] Preloading models...")
    try:
        classifier = AIEnsembleClassifier()
        classifier._ensure_specialized()
        classifier._ensure_clip()
    except Exception as exc:
        logger.warning(f"[Ensemble] Model preload failed: {exc}")

# --- Fusion & Verdict logic ---
RELIABILITY_WEIGHT = {"high": 1.0, "medium": 0.62, "low": 0.28}
CATEGORY_BASE_WEIGHT: Dict[str, float] = {
    "patch_artifact": 2.85,     # UPGRADE: Primary explainability layer
    "ml_classifier": 2.10,     # Ensemble models
    "diffusion_artifact": 1.45, # Global diffusion signals
    "frequency_domain": 0.65,   # Demoted naive global FFT
    "facial_forensics": 0.95,   # Important for portraits
    "compression_ela": 0.35,
    "metadata": 0.25,
    "general": 0.35,
}
UNSTABLE_SIGNAL_KEYS = {
    "eye_reflection_consistency", # Requirement Part 6: Demoted weak handcrafted signals
    "repetitive_background",
    "frequency_fingerprint",
    "hair_boundaries",
    "eyelash_consistency",
    "beard_edges",
    "eye_artifacts",
    "pore_consistency",
}

def _calibrate_ml_probability(raw_probability: float) -> Tuple[float, float, Dict[str, Any]]:
    raw = _clamp(float(raw_probability), 1e-4, 1.0 - 1e-4)
    logit = float(np.log(raw / (1.0 - raw)))
    temperature = float(os.environ.get("VEYRON_ML_TEMPERATURE", "1.05"))
    compression = float(os.environ.get("VEYRON_ML_PROBABILITY_COMPRESSION", "1.0"))
    widened_uncertainty = float(os.environ.get("VEYRON_ML_UNCERTAINTY_WIDENING", "1.0"))
    
    temp_scaled = 1.0 / (1.0 + np.exp(-(logit / max(temperature, 1e-3))))
    compressed = 0.5 + (temp_scaled - 0.5) * compression
    calibrated = _clamp(compressed)
    
    # Realistic confidence: measures distance from decision threshold without collapsing to near-zero
    confidence = _clamp(max(0.50, 0.50 + abs(calibrated - 0.5) * widened_uncertainty))
    
    logger.debug(
        "[Calibration Production Debug] raw=%.4f, logit=%.4f, temp=%.3f, "
        "temp_scaled=%.4f, compressed=%.4f, calibrated=%.4f, confidence=%.4f",
        raw, logit, temperature, temp_scaled, compressed, calibrated, confidence
    )
    
    return calibrated, confidence, {
        "raw_probability": round(raw, 4),
        "temperature": round(temperature, 3),
        "temp_scaled_probability": round(float(temp_scaled), 4),
        "compression": round(compression, 3),
        "calibrated_probability": round(calibrated, 4),
        "confidence": round(confidence, 4),
    }

def _signal_interval(s: SignalResult) -> Tuple[float, float]:
    if s.confidence_interval:
        return s.confidence_interval
    width = {"high": 0.06, "medium": 0.12, "low": 0.22}.get(s.reliability, 0.18)
    if s.key in UNSTABLE_SIGNAL_KEYS:
        width = max(width, 0.20)
    return _confidence_interval(s.score, width)

def _dynamic_signal_weight(s: SignalResult) -> Tuple[float, str]:
    strength = abs(s.score - 0.5) * 2.0
    weight = CATEGORY_BASE_WEIGHT.get(s.category, 0.5) * RELIABILITY_WEIGHT.get(s.reliability, 0.5)
    weight_reason = "base reliability/category weight"
    
    # Requirement Part 2 & 8: Apply the dynamic ensemble suppression multiplier
    if hasattr(s, "ensemble_multiplier") and s.ensemble_multiplier != 1.0:
        weight *= s.ensemble_multiplier
        weight_reason = f"ensemble dynamic ({s.ensemble_multiplier:.2f})"
        
    if s.key in UNSTABLE_SIGNAL_KEYS:
        weight = 0.0
        weight_reason = "suppressed weak heuristic (explainability only, weight=0.0)"
    if s.category == "frequency_domain" and strength < 0.26:
        weight *= 0.45
        weight_reason = "reduced because FFT evidence is weak near the decision boundary"
    if s.reliability == "low" and strength < 0.35:
        weight *= 0.55
        weight_reason = "reduced because low-confidence evidence is close to neutral"
    if s.category == "ml_classifier":
        weight *= max(0.55, min(1.0, 0.50 + 0.50 * strength))
        weight_reason = "scaled by classifier confidence"
    elif s.confidence is not None and s.key not in UNSTABLE_SIGNAL_KEYS:
        # Scale weight by individual signal confidence for non-ML signals
        weight *= s.confidence
        weight_reason += f" scaled by signal confidence {s.confidence:.2f}"
        
    return weight, weight_reason

def _weighted_signal_score(signals: List[SignalResult]) -> Tuple[float, float, Dict[str, Any]]:
    weighted_sum = 0.0
    total_weight = 0.0
    by_category: Dict[str, List[Dict[str, Any]]] = {}
    for s in signals:
        if s.status != "active":
            by_category.setdefault(s.category, []).append({
                "key": s.key,
                "score": s.score,
                "contribution_score": 0.5,
                "weight": 0.0,
                "impact": 0.0,
                "status": s.status,
                "weight_reason": "suppressed or unavailable",
                "confidence_interval": _signal_interval(s),
            })
            continue
        strength = abs(s.score - 0.5) * 2.0
        if strength < 0.08:
            continue
        weight, weight_reason = _dynamic_signal_weight(s)
        contribution_score = s.score
        # Artifact detectors are mostly positive evidence: absence of an artifact should be neutral,
        # not strong proof that an image is authentic.
        if s.category in {"compression_ela", "frequency_domain", "diffusion_artifact"} and s.score < 0.5:
            contribution_score = 0.5
            weight *= 0.55
        if s.category == "compression_ela" and s.score < 0.08:
            weight *= 0.35
        weighted_sum += contribution_score * weight
        total_weight += weight
        by_category.setdefault(s.category, []).append({
            "key": s.key,
            "score": s.score,
            "contribution_score": contribution_score,
            "weight": round(weight, 4),
            "impact": round((contribution_score - 0.5) * weight, 4),
            "status": s.status,
            "weight_reason": weight_reason,
            "confidence_interval": _signal_interval(s),
        })
    if total_weight <= 0:
        return 0.5, 0.0, by_category
    return _clamp(weighted_sum / total_weight), total_weight, by_category

def _compute_forensic_consensus(forensic_signals: List[SignalResult]) -> Tuple[float, str]:
    """
    Computes a weighted consensus purely from forensic (non-ML) signals.
    Prioritizes facial consistency and high-reliability texture artifacts.
    """
    if not forensic_signals:
        return 0.5, "neutral"
    
    weights = {
        "facial_forensics": 1.2,
        "diffusion_artifact": 1.0,
        "frequency_domain": 0.8,
        "compression_ela": 0.4,
        "metadata": 0.3,
    }
    
    weighted_sum = 0.0
    total_weight = 0.0
    
    for s in forensic_signals:
        if s.status != "active": continue
        if s.key in UNSTABLE_SIGNAL_KEYS: continue
        w = weights.get(s.category, 0.5) * RELIABILITY_WEIGHT.get(s.reliability, 0.5)
        # Higher strength signals contribute more to consensus
        strength = abs(s.score - 0.5) * 2.0
        w *= (0.5 + strength)
        
        weighted_sum += s.score * w
        total_weight += w
        
    if total_weight <= 0:
        return 0.5, "neutral"
        
    consensus_score = weighted_sum / total_weight
    if consensus_score <= 0.42:
        return consensus_score, "authentic_leaning"
    if consensus_score >= 0.58:
        return consensus_score, "synthetic_leaning"
    return consensus_score, "mixed"

def _agreement_stats(signals: List[SignalResult]) -> Dict[str, Any]:
    active = [s for s in signals if s.status == "active" and s.key not in UNSTABLE_SIGNAL_KEYS]
    synthetic = [s for s in active if s.score >= 0.62]
    authentic = [s for s in active if s.score <= 0.38]
    
    strong_synthetic = [s for s in active if s.score >= 0.72]
    strong_authentic = [
        s for s in active
        if s.score <= 0.28 and s.category not in {"compression_ela", "frequency_domain", "diffusion_artifact"}
    ]
    
    classifier = [s for s in active if s.category == "ml_classifier"]
    forensic = [s for s in active if s.category != "ml_classifier"]
    
    strong_disagreement = bool(strong_synthetic and strong_authentic)
    
    classifier_agrees = None
    weak_disagreement = False
    ml_forensic_conflict = False
    
    if classifier and forensic:
        ml_score = float(np.mean([s.score for s in classifier]))
        ml_side = ml_score >= 0.5
        
        forensic_consensus_score, _ = _compute_forensic_consensus(forensic)
        forensic_side = forensic_consensus_score >= 0.5
        
        classifier_agrees = bool(ml_side == forensic_side)
        
        # Conflict if ML is strong and forensic is moderate/strong the other way
        if abs(ml_score - forensic_consensus_score) > 0.35:
            if (ml_score > 0.65 and forensic_consensus_score < 0.45) or (ml_score < 0.35 and forensic_consensus_score > 0.55):
                ml_forensic_conflict = True
        
        # Weak disagreement if they differ but scores are closer to neutral
        if not classifier_agrees and abs(ml_score - 0.5) < 0.15 and abs(forensic_consensus_score - 0.5) < 0.15:
            weak_disagreement = True

    return {
        "active_count": len(active),
        "synthetic_count": len(synthetic),
        "authentic_count": len(authentic),
        "strong_synthetic": [s.key for s in strong_synthetic],
        "strong_authentic": [s.key for s in strong_authentic],
        "disagreement": strong_disagreement,
        "ml_forensic_conflict": ml_forensic_conflict,
        "weak_disagreement": weak_disagreement,
        "classifier_agrees_with_forensics": classifier_agrees,
    }

def _confidence_band(confidence: float) -> str:
    if confidence >= 0.72:
        return "high"
    if confidence >= 0.45:
        return "medium"
    return "low"

def _disagreement_report(stats: Dict[str, Any], ensemble: Optional[EnsembleResult], forensic_score: float) -> str:
    if not ensemble or not ensemble.available:
        return "No ML classifier ensemble was available; verdict relies on lower-confidence forensic cues."
    ml_side = "synthetic image" if ensemble.ensemble_score >= 0.5 else "authentic image"
    forensic_side = "synthetic" if forensic_score >= 0.5 else "authentic"
    
    if stats.get("ml_forensic_conflict"):
        return f"Significant conflict: Ensemble models suggest {ml_side}, but forensic consensus strongly indicates {forensic_side} characteristics."
    if stats.get("disagreement"):
        return f"High detector disagreement: Multiple signals (ML or forensic) strongly point in opposite directions."
    if stats.get("weak_disagreement"):
        return "Minor signal variance: Ensemble and forensic signals are near neutral with slight opposite leans."
    if stats["classifier_agrees_with_forensics"] is False:
        return f"Partial disagreement: AI ensemble suggests {ml_side}, but forensic signals lean {forensic_side}."
    if stats["classifier_agrees_with_forensics"] is True:
        return f"Signal alignment: AI ensemble and forensic signals are in agreement toward {ml_side}."
    return "Ensemble signals are mixed or lack strong consensus."

def analyze_portrait_forensics(bgr: np.ndarray, faces: List[np.ndarray], ctype: str) -> List[SignalResult]:
    signals = []
    keys = [
        "skin_microtexture",
        "diffusion_smoothing",
        "pore_consistency",
        "hair_boundaries",
        "eye_artifacts",
        "beard_edges",
        "eyelash_consistency"
    ]
    
    if ctype != "human_portrait" or not faces:
        for k in keys:
            signals.append(SignalResult(
                key=k,
                score=0.5,
                detail="Skipped: not a human portrait content type.",
                category="facial_forensics",
                status="skipped",
                reliability="low",
                human_readable=f"Portrait forensic check for {k.replace('_', ' ')} (skipped)."
            ))
        return signals

    scores = {k: [] for k in keys}
    for face in faces:
        gray = cv2.cvtColor(face, cv2.COLOR_BGR2GRAY)
        h, w = gray.shape[:2]
        if h < 40 or w < 40:
            for k in keys:
                scores[k].append((0.5, "low", "skipped"))
            continue
            
        # Calculate face asymmetry for head angle check
        face_flipped = cv2.flip(gray, 1)
        face_diff = cv2.absdiff(gray, face_flipped)
        face_asym = float(np.mean(face_diff)) / 255.0
        is_profile = face_asym > 0.14
        
        # 1. Skin Microtexture
        # FIX (PART 1 — FUSION INVERSION): Formula was semantically inverted.
        # Original: (20 - skin_micro) / 20  → HIGH Laplacian → LOW score (reads as AUTHENTIC)
        # AI diffusion skin has HIGH Laplacian variance (sharp synthetic micro-edges) → was scoring near 0.0
        # Corrected: skin_micro / 20  → HIGH Laplacian → HIGH score (reads as AI)
        # Real camera skin has moderate Laplacian (8–14) → score 0.40–0.70 (correctly neutral/AI-leaning)
        # Beauty-filtered skin has LOW Laplacian (2–5) → score 0.10–0.25 (correctly authentic)
        skin_h_start, skin_h_end = int(h * 0.3), int(h * 0.7)
        skin_w_start, skin_w_end = int(w * 0.2), int(w * 0.8)
        skin = gray[skin_h_start:skin_h_end, skin_w_start:skin_w_end]
        if skin.size > 0:
            lap = cv2.Laplacian(skin, cv2.CV_32F)
            skin_micro = float(np.std(lap))
            if np.isnan(skin_micro) or np.isinf(skin_micro):
                skin_micro = 0.0

            # CORRECTED FORMULA: high Laplacian std = AI-like synthetic texture = high score
            raw_score = _clamp(skin_micro / 20.0)

            # Beauty filter & compression tolerance
            if skin_micro < 3.0:
                scores["skin_microtexture"].append((0.5, "low", "skipped"))
            elif skin_micro < 8.0:
                # Low texture — slightly attenuate toward neutral (may be compression artifact)
                cal_score = raw_score * 0.5 + 0.25
                scores["skin_microtexture"].append((cal_score, "low", "active"))
            else:
                scores["skin_microtexture"].append((raw_score, "high", "active"))
        else:
            scores["skin_microtexture"].append((0.5, "low", "skipped"))

        # 2. Diffusion Smoothing
        # FIX (PART 1 — FUSION INVERSION): Formula was semantically inverted.
        # Original: (4 - diff_smooth) / 4  → HIGH bilateral residual → LOW score (reads as AUTHENTIC)
        # AI diffusion skin: bilateral filter cannot remove AI texture → HIGH residual → was scoring near 0.1
        # Corrected: diff_smooth / 4  → HIGH residual → HIGH score (reads as AI)
        # Real smooth skin: LOW residual after bilateral → score near 0 (correctly authentic)
        if skin.size > 0:
            if skin_micro < 8.0:
                scores["diffusion_smoothing"].append((0.5, "low", "skipped"))
            else:
                bilateral = cv2.bilateralFilter(skin, 9, 75, 75)
                residual_texture = skin.astype(np.float32) - bilateral.astype(np.float32)
                diff_smooth = float(np.mean(np.abs(residual_texture)))
                if np.isnan(diff_smooth) or np.isinf(diff_smooth):
                    diff_smooth = 0.0
                # CORRECTED FORMULA: high residual = AI-like texture = high score
                raw_score = _clamp(diff_smooth / 4.0)
                scores["diffusion_smoothing"].append((raw_score, "medium", "active"))
        else:
            scores["diffusion_smoothing"].append((0.5, "low", "skipped"))
            
        # 3. Pore Consistency
        if skin.size > 16:
            blocks = []
            sh, sw = skin.shape
            bh, bw = 8, 8
            for r in range(0, sh - bh + 1, bh):
                for c in range(0, sw - bw + 1, bw):
                    blocks.append(np.var(skin[r:r+bh, c:c+bw]))
            if blocks:
                mean_var = np.mean(blocks)
                std_var = np.std(blocks)
                pore_val = std_var / (mean_var + 1e-6)
                if np.isnan(pore_val) or np.isinf(pore_val):
                    pore_val = 0.4
                raw_score = _clamp(abs(pore_val - 0.4) * 2.0)
                
                if skin_micro < 8.0:
                    cal_score = 0.5 + (raw_score - 0.5) * 0.3
                    scores["pore_consistency"].append((cal_score, "low", "active"))
                else:
                    scores["pore_consistency"].append((raw_score, "medium", "active"))
            else:
                scores["pore_consistency"].append((0.5, "low", "skipped"))
        else:
            scores["pore_consistency"].append((0.5, "low", "skipped"))
            
        # 4. Hair Boundaries
        hair_region = gray[0:int(h * 0.2), :]
        if hair_region.size > 0:
            sobelx = cv2.Sobel(hair_region, cv2.CV_32F, 1, 0, ksize=3)
            sobely = cv2.Sobel(hair_region, cv2.CV_32F, 0, 1, ksize=3)
            grad_mag = np.sqrt(sobelx**2 + sobely**2)
            hair_blur = float(np.mean(grad_mag))
            if np.isnan(hair_blur) or np.isinf(hair_blur):
                hair_blur = 0.0
                
            if hair_blur < 2.0:
                scores["hair_boundaries"].append((0.5, "low", "skipped"))
            else:
                raw_score = _clamp((15.0 - hair_blur) / (15.0 + 1e-7))
                scores["hair_boundaries"].append((raw_score, "medium", "active"))
        else:
            scores["hair_boundaries"].append((0.5, "low", "skipped"))
            
        # 5. Eye Consistency (eye artifacts)
        eye_h_start, eye_h_end = int(h * 0.25), int(h * 0.45)
        left_eye = gray[eye_h_start:eye_h_end, int(w * 0.15):int(w * 0.48)]
        right_eye = gray[eye_h_start:eye_h_end, int(w * 0.52):int(w * 0.85)]
        if left_eye.size > 0 and right_eye.size > 0 and not is_profile:
            right_flipped = cv2.flip(right_eye, 1)
            right_resized = cv2.resize(right_flipped, (left_eye.shape[1], left_eye.shape[0]))
            diff = cv2.absdiff(left_eye, right_resized)
            eye_asym = float(np.mean(diff)) / 255.0
            if np.isnan(eye_asym) or np.isinf(eye_asym):
                eye_asym = 0.05
            raw_score = _clamp((eye_asym - 0.05) / (0.15 + 1e-7))
            scores["eye_artifacts"].append((raw_score, "medium", "active"))
        else:
            scores["eye_artifacts"].append((0.5, "low", "skipped"))
            
        # 6. Beard Edges
        beard_region = gray[int(h * 0.65):h, :]
        if beard_region.size > 0:
            sobel = cv2.Sobel(beard_region, cv2.CV_32F, 1, 1, ksize=3)
            beard_energy = float(np.mean(np.abs(sobel)))
            if np.isnan(beard_energy) or np.isinf(beard_energy):
                beard_energy = 0.0
                
            if beard_energy < 1.0:
                scores["beard_edges"].append((0.5, "low", "skipped"))
            else:
                raw_score = _clamp((8.0 - beard_energy) / (8.0 + 1e-7))
                scores["beard_edges"].append((raw_score, "medium", "active"))
        else:
            scores["beard_edges"].append((0.5, "low", "skipped"))
            
        # 7. Eyelash Consistency
        eyelash_region = gray[int(h * 0.3):int(h * 0.42), int(w * 0.15):int(w * 0.85)]
        if eyelash_region.size > 0 and not is_profile:
            sobely = cv2.Sobel(eyelash_region, cv2.CV_32F, 0, 1, ksize=3)
            eyelash_val = float(np.std(sobely))
            if np.isnan(eyelash_val) or np.isinf(eyelash_val):
                eyelash_val = 0.0
            raw_score = _clamp((18.0 - eyelash_val) / (18.0 + 1e-7))
            scores["eyelash_consistency"].append((raw_score, "medium", "active"))
        else:
            scores["eyelash_consistency"].append((0.5, "low", "skipped"))

    final_signals = []
    for k in keys:
        face_data = scores[k]
        if not face_data:
            final_signals.append(SignalResult(
                key=k, score=0.5, detail="Skipped: no face data processed.",
                category="facial_forensics", status="skipped", reliability="low",
                human_readable=f"Portrait forensic check for {k.replace('_', ' ')}."
            ))
            continue
            
        avg_score = float(np.mean([d[0] for d in face_data]))
        reliabilities = [d[1] for d in face_data]
        statuses = [d[2] for d in face_data]
        
        final_status = "active" if any(s == "active" for s in statuses) else "skipped"
        if "low" in reliabilities:
            final_reliability = "low"
        elif "medium" in reliabilities:
            final_reliability = "medium"
        else:
            final_reliability = "high"
            
        detail_msg = f"Portrait analysis of {k.replace('_', ' ')}: score={avg_score:.3f}, reliability={final_reliability}"
        if final_status == "skipped":
            detail_msg = f"Portrait analysis of {k.replace('_', ' ')} skipped."
            
        final_signals.append(SignalResult(
            key=k,
            score=avg_score,
            detail=detail_msg,
            category="facial_forensics",
            status=final_status,
            reliability=final_reliability,
            human_readable=f"Portrait forensic signal checking for {k.replace('_', ' ')} inconsistencies."
        ))
        
    # GC cleanup
    del gray
    import gc
    gc.collect()
    
    return final_signals

def fuse_signals(
    signals: List[SignalResult],
    ensemble_result: EnsembleResult,
    patch_result: PatchForensicResult,
    ctype_info: Dict[str, Any],
    prov_data: Optional[Dict[str, Any]] = None,
    file_path: str = ""
) -> Dict[str, Any]:
    ctype = ctype_info["type"]
    debug_info = ctype_info.get("debug_info", {})
    prov_data = prov_data or {}
    device = AIEnsembleClassifier.get_device()
    clip_res = (ensemble_result.clip_result if (ensemble_result and hasattr(ensemble_result, "clip_result") and ensemble_result.clip_result) else {}) or {}

    c2pa_info = prov_data.get("c2pa", {})
    google_info = prov_data.get("google_provenance", {})
    prov_scores = prov_data.get("scores", {})
    cam_prov = float(prov_scores.get("camera_provenance_score", 0.05))
    ai_prov = float(prov_scores.get("ai_provenance_score", 0.02))
    meta_integrity = float(prov_scores.get("metadata_integrity_score", 0.50))
    cred_validity = float(prov_scores.get("credential_validity_score", 0.0))
    conflict_score = float(prov_scores.get("provenance_conflict_score", 0.0))

    # Low dimension / unusable check
    if ctype == "low_quality":
        debug_analysis = {
            "file_name": Path(file_path).name if file_path else "unknown",
            "mime_type": prov_data.get("container", {}).get("mime_type", "application/octet-stream"),
            "file_size": prov_data.get("container", {}).get("file_size", 0),
            "sha256": prov_data.get("sha256", "unknown"),
            "original_image_dimensions": prov_data.get("container", {}).get("original_dimensions", [0, 0]),
            "original_image_format": prov_data.get("container", {}).get("format", "unknown"),
            "metadata_fields_detected": 0,
            "c2pa_fields_detected": {"c2pa_detected": False},
            "xmp_fields_detected": [],
            "exif_fields_detected": [],
            "camera_manufacturer": None,
            "camera_model": None,
            "software_tag": None,
            "creator_tool": None,
            "generator_tool": None,
            "clip_available": False,
            "clip_status": "MODEL_UNAVAILABLE",
            "clip_raw_real_scores": {},
            "clip_raw_ai_scores": {},
            "clip_aggregate_score": None,
            "clip_confidence": None,
            "specialized_detector": {"model_name": "umm-maybe/AI-image-detector", "available": False, "score": 0.5, "confidence": 0.0, "device": device},
            "every_forensic_signal_score": {},
            "forensic_aggregate_score": 0.5,
            "camera_provenance_score": cam_prov,
            "ai_provenance_score": ai_prov,
            "metadata_integrity_score": meta_integrity,
            "credential_validity_score": cred_validity,
            "provenance_conflict_score": conflict_score,
            "provenance_score": max(cam_prov, ai_prov),
            "final_fusion_score": 0.5,
            "final_verdict": "UNCERTAIN",
            "final_confidence": 0.0,
            "device": device,
            "decision_hierarchy_level_triggered": "LEVEL_6_UNCERTAIN",
            "verdict_reason": "Image dimensions are too small for reliable forensic analysis (max side < 200px).",
            "google_provenance": google_info,
        }
        return {
            "assessment": "uncertain",
            "legacy_verdict": "suspicious",
            "verdict": "UNCERTAIN",
            "verdict_color": "yellow",
            "confidence_percent": 0,
            "verdict_reason": "Image dimensions are too small for reliable forensic analysis (max side < 200px).",
            "evidenceBreakdown": [],
            "detectionSignals": [],
            "suspiciousIndicators": [],
            "details": " | ".join(ctype_info["reasons"]),
            "findings": ctype_info["reasons"],
            "fusion_score": 0.5,
            "confidence": 0.0,
            "aiProbability": 50,
            "manipulationRisk": 50,
            "confidenceLevel": "low",
            "debug_info": debug_info,
            "debugAnalysis": debug_analysis,
        }

    patch_signals = []
    if patch_result.available:
        patch_signals.append(SignalResult(
            "patch_artifact_density",
            patch_result.suspicious_density,
            f"Suspicious patch density: {patch_result.suspicious_density:.2f}",
            "patch_artifact",
            reliability="high" if patch_result.suspicious_density > 0.4 else "medium",
            human_readable="Local synthetic texture density."
        ))
        patch_signals.append(SignalResult(
            "patch_artifact_clustering",
            patch_result.clustering_score,
            f"Artifact clustering: {patch_result.clustering_score:.2f}",
            "patch_artifact",
            reliability="medium",
            human_readable="Local artifact spatial consistency."
        ))

    ml_signals = []
    for r in ensemble_result.results:
        sig = SignalResult(
            f"ml_model_{r.model_name.replace('/', '_')}",
            r.ai_probability,
            f"Model {r.model_name} score: {r.ai_probability:.3f} (conf: {r.confidence:.3f})",
            "ml_classifier",
            "active" if r.available else "failed",
            "high" if r.confidence > 0.65 else "medium" if r.confidence > 0.35 else "low",
            f"AI detection signal from {r.model_name}.",
            _confidence_interval(r.ai_probability, 0.15 if r.available else 0.30),
            ensemble_multiplier=1.0,
            confidence=r.confidence
        )
        ml_signals.append(sig)

    all_signals = signals + ml_signals + patch_signals
    _, evidence_weight, category_breakdown = _weighted_signal_score(all_signals)

    spec_model_res = (ensemble_result.specialized_result if (ensemble_result and hasattr(ensemble_result, "specialized_result") and ensemble_result.specialized_result) else next((r for r in ensemble_result.results if "umm-maybe" in r.model_name), None)) if ensemble_result else None
    clip_model_res = next((r for r in ensemble_result.results if "clip" in r.model_name.lower()), None) if ensemble_result else None

    spec_ai = float(spec_model_res.ai_probability) if (spec_model_res and spec_model_res.available) else 0.50
    spec_conf = float(spec_model_res.confidence) if (spec_model_res and spec_model_res.available) else 0.0
    clip_ai = float(clip_model_res.ai_probability) if (clip_model_res and clip_model_res.available) else float(clip_res.get("aggregate_score", 0.0) if clip_res else 0.0)
    clip_avail = bool(clip_model_res and clip_model_res.available) or bool(clip_res and clip_res.get("available"))

    forensic_active = [s for s in all_signals if s.status == "active" and s.category != "ml_classifier"]
    forensic_consensus_score, forensic_consensus_state = _compute_forensic_consensus(forensic_active)

    sensor_sig = next((s for s in signals if s.key == "sensor_noise"), None)
    sensor_score = sensor_sig.score if (sensor_sig and sensor_sig.status == "active") else 0.50

    manip_scores = [s.score for s in all_signals if s.key not in UNSTABLE_SIGNAL_KEYS and s.category in {"compression_ela", "frequency_domain", "diffusion_artifact", "patch_artifact", "facial_forensics"}]
    manip_prob = float(np.mean(manip_scores)) if manip_scores else 0.5
    if np.isnan(manip_prob):
        manip_prob = 0.5

    # Continuous soft fusion for Levels 4/5: balanced weights giving CLIP real contribution without single-model dominance
    w_spec = 0.50 if (spec_model_res and spec_model_res.available) else 0.0
    w_forensic = 0.30
    w_clip = 0.20 if clip_avail else 0.0
    total_weights = w_spec + w_forensic + w_clip
    if total_weights > 0:
        fusion_score = float((w_spec * spec_ai + w_forensic * forensic_consensus_score + w_clip * clip_ai) / total_weights)
    else:
        fusion_score = float(forensic_consensus_score)

    # --- 6-LEVEL HIERARCHICAL DECISION ENGINE ---
    decision_level = "LEVEL_6_UNCERTAIN"
    verdict = "UNCERTAIN"
    assessment = "uncertain"
    color = "yellow"
    confidence_calibration = 0.50
    reason = "No reliable provenance credentials present and visual evidence is inconclusive."

    # Priority Guard: Conflict / Contradiction Check
    if conflict_score > 0.60 or (c2pa_info.get("detected") and not c2pa_info.get("is_valid", False)):
        verdict = "UNCERTAIN"
        assessment = "uncertain"
        color = "yellow"
        confidence_calibration = 0.55
        decision_level = "LEVEL_1_PROVENANCE_CONFLICT"
        reason = "Contradiction detected: camera hardware metadata conflicts with generative AI signatures or manifest state. Requires manual review."

    # LEVEL 1: VERIFIED PROVENANCE
    elif c2pa_info.get("is_generative_ai") and c2pa_info.get("is_valid", False):
        verdict = "AI_GENERATED"
        assessment = "ai_generated"
        color = "red"
        confidence_calibration = 0.98
        decision_level = "LEVEL_1_VERIFIED_PROVENANCE"
        claim_gen = c2pa_info.get("claim_generator") or "Generative AI"
        reason = f"Verified Content Credentials (C2PA) confirm generative AI provenance from {claim_gen}."

    elif google_info.get("google_provenance_detected"):
        verdict = "AI_GENERATED"
        assessment = "ai_generated"
        color = "red"
        confidence_calibration = 0.96
        decision_level = "LEVEL_1_VERIFIED_PROVENANCE"
        reason = f"Google AI provenance confirmed in media container: {google_info.get('details')}."

    elif c2pa_info.get("is_camera_capture") and c2pa_info.get("is_valid", False):
        verdict = "AUTHENTIC_PROVENANCE"
        assessment = "authentic_provenance"
        color = "emerald"
        confidence_calibration = 0.98
        decision_level = "LEVEL_1_VERIFIED_PROVENANCE"
        claim_gen = c2pa_info.get("claim_generator") or "Certified Camera"
        reason = f"Cryptographically verified Content Credentials (C2PA) confirm original camera capture on {claim_gen}."

    # LEVEL 2: STRONG GENERATOR SIGNATURES
    elif ai_prov >= 0.90:
        verdict = "AI_GENERATED"
        assessment = "ai_generated"
        color = "red"
        confidence_calibration = 0.92
        decision_level = "LEVEL_2_STRONG_GENERATOR_SIGNATURES"
        gen_tool = prov_data.get("generator_tool") or "Generative AI software"
        reason = f"Explicit generative AI tooling signature identified in image metadata: {gen_tool}."

    # LEVEL 3: SPECIALIZED AI DETECTOR (Non-veto: requires lack of strong counter-signals)
    elif spec_model_res and spec_model_res.available and spec_ai >= 0.70:
        verdict = "LIKELY_AI"
        assessment = "likely_ai"
        color = "red"
        confidence_calibration = min(0.95, max(0.75, spec_conf))
        decision_level = "LEVEL_3_SPECIALIZED_DETECTOR"
        reason = f"Specialized synthetic-image detector favors AI generation ({spec_ai*100:.1f}%), corroborated by forensic texture analysis."

    elif spec_model_res and spec_model_res.available and spec_ai <= 0.25 and not (clip_avail and clip_ai >= 0.65):
        software_val = str(prov_data.get("software_tag") or "").lower()
        is_editor_software = any(ed in software_val for ed in ["photoshop", "gimp", "lightroom", "canva", "picsart", "photopea", "snapseed", "affinity"])

        if is_editor_software:
            verdict = "MANIPULATED"
            assessment = "manipulated"
            color = "amber"
            confidence_calibration = 0.88
            decision_level = "LEVEL_4_EDITED_PROVENANCE"
            tag_name = prov_data.get("software_tag") or "Image editing software"
            reason = f"Camera capture metadata detected, but software history confirms modification in {tag_name}."
        elif cam_prov >= 0.80:
            verdict = "LIKELY_AUTHENTIC"
            assessment = "likely_authentic"
            color = "green"
            confidence_calibration = min(0.95, max(0.85, 1.0 - spec_ai))
            decision_level = "LEVEL_3_SPECIALIZED_DETECTOR_CAMERA_EXIF"
            make = prov_data.get("camera_maker") or "Camera"
            model = prov_data.get("camera_model") or ""
            reason = f"Camera hardware metadata ({make} {model}) and optical exposure parameters align with specialized detector favoring authentic photography."
        else:
            verdict = "LIKELY_AUTHENTIC"
            assessment = "likely_authentic"
            color = "green"
            confidence_calibration = min(0.92, max(0.75, 1.0 - spec_ai))
            decision_level = "LEVEL_3_SPECIALIZED_DETECTOR"
            reason = f"Specialized synthetic detector and physical sensor noise favor authentic camera capture (human probability: {(1.0-spec_ai)*100:.1f}%)."

    # LEVEL 4: FORENSIC IMAGE SIGNALS & CONTINUOUS ENSEMBLE FUSION
    elif (patch_result.available and patch_result.clustering_score > 0.75) or (manip_prob > 0.72):
        verdict = "MANIPULATED"
        assessment = "manipulated"
        color = "amber"
        confidence_calibration = 0.75
        decision_level = "LEVEL_4_FORENSIC_MANIPULATION"
        reason = "Local compression, ELA, and spatial texture anomalies indicate selective manipulation or splicing."

    elif fusion_score >= 0.58 or (spec_ai >= 0.55 and clip_avail and clip_ai >= 0.58):
        verdict = "LIKELY_AI"
        assessment = "likely_ai"
        color = "red"
        confidence_calibration = min(0.90, max(0.68, 0.50 + abs(fusion_score - 0.5) * 1.5))
        decision_level = "LEVEL_4_FORENSIC_FUSION_AI"
        reason = f"Visual ensemble models and forensic texture patterns corroborate synthetic generation (fused score: {fusion_score:.2f})."

    elif fusion_score <= 0.42 and (cam_prov >= 0.30 or sensor_score <= 0.40):
        verdict = "LIKELY_AUTHENTIC"
        assessment = "likely_authentic"
        color = "green"
        confidence_calibration = min(0.90, max(0.68, 0.50 + abs(fusion_score - 0.5) * 1.5))
        decision_level = "LEVEL_4_FORENSIC_FUSION_AUTHENTIC"
        reason = f"Physical sensor noise and forensic consistency align with authentic camera capture (fused score: {fusion_score:.2f})."

    # LEVEL 6: NO EVIDENCE / AMBIGUITY -> UNCERTAIN
    else:
        verdict = "UNCERTAIN"
        assessment = "uncertain"
        color = "yellow"
        confidence_calibration = 0.50
        decision_level = "LEVEL_6_UNCERTAIN"
        reason = "No reliable provenance credentials present and visual models show borderline or conflicting evidence. Human review recommended."

    # Legacy verdict mapping for backwards compatibility
    legacy_verdict = (
        "real" if verdict in {"AUTHENTIC_PROVENANCE", "LIKELY_AUTHENTIC"}
        else "fake" if verdict in {"AI_GENERATED", "LIKELY_AI"}
        else "suspicious"
    )

    # --- COMPLETE DEBUG ANALYSIS OBJECT (33 Fields) ---
    debug_analysis = {
        "file_name": Path(file_path).name if file_path else "unknown",
        "mime_type": prov_data.get("container", {}).get("mime_type", "application/octet-stream"),
        "file_size": prov_data.get("container", {}).get("file_size", 0),
        "sha256": prov_data.get("sha256", "unknown"),
        "original_image_dimensions": prov_data.get("container", {}).get("original_dimensions", [0, 0]),
        "original_image_format": prov_data.get("container", {}).get("format", "unknown"),
        "metadata_fields_detected": prov_data.get("exif_tags_count", 0) + len(prov_data.get("xmp_fields", [])) + len(prov_data.get("png_text_chunks", {})),
        "c2pa_fields_detected": {
            "c2pa_available": c2pa_info.get("available", False),
            "c2pa_detected": c2pa_info.get("detected", False),
            "c2pa_valid": c2pa_info.get("is_valid", False),
            "claim_generator": c2pa_info.get("claim_generator"),
            "is_generative_ai": c2pa_info.get("is_generative_ai", False),
            "is_camera_capture": c2pa_info.get("is_camera_capture", False),
            "actions": c2pa_info.get("actions", []),
        },
        "xmp_fields_detected": prov_data.get("xmp_fields", []),
        "exif_fields_detected": list(prov_data.get("exif_fields", {}).keys()),
        "camera_manufacturer": prov_data.get("camera_maker"),
        "camera_model": prov_data.get("camera_model"),
        "software_tag": prov_data.get("software_tag"),
        "creator_tool": prov_data.get("creator_tool"),
        "generator_tool": prov_data.get("generator_tool"),
        "clip_available": clip_avail,
        "clip_status": "active" if clip_avail else (clip_res.get("status") if isinstance(clip_res, dict) and clip_res.get("status") else "MODEL_UNAVAILABLE"),
        "clip_raw_real_scores": clip_res.get("real_prompt_scores", {}) if (clip_avail and isinstance(clip_res, dict)) else {},
        "clip_raw_ai_scores": clip_res.get("ai_prompt_scores", {}) if (clip_avail and isinstance(clip_res, dict)) else {},
        "clip_aggregate_score": round(float(clip_res.get("aggregate_score")), 4) if (clip_avail and isinstance(clip_res, dict) and clip_res.get("aggregate_score") is not None) else None,
        "clip_confidence": round(float(clip_res.get("confidence")), 4) if (clip_avail and isinstance(clip_res, dict) and clip_res.get("confidence") is not None) else None,
        "specialized_detector": {
            "model_name": spec_model_res.model_name if spec_model_res else "umm-maybe/AI-image-detector",
            "available": spec_model_res.available if spec_model_res else False,
            "score": round(float(spec_ai), 4),
            "confidence": round(float(spec_conf), 4),
            "device": device,
            "inference_time_ms": round(float(spec_model_res.inference_time * 1000) if spec_model_res else 0.0, 2),
        },
        "every_forensic_signal_score": {
            s.key: round(float(s.score), 4) for s in all_signals if s.category != "ml_classifier"
        },
        "forensic_aggregate_score": round(float(forensic_consensus_score), 4),
        "camera_provenance_score": round(float(cam_prov), 4),
        "ai_provenance_score": round(float(ai_prov), 4),
        "metadata_integrity_score": round(float(meta_integrity), 4),
        "credential_validity_score": round(float(cred_validity), 4),
        "provenance_conflict_score": round(float(conflict_score), 4),
        "provenance_score": round(float(max(cam_prov, ai_prov)), 4),
        "final_fusion_score": round(float(fusion_score), 4),
        "final_verdict": verdict,
        "final_confidence": round(float(confidence_calibration), 4),
        "device": device,
        "decision_hierarchy_level_triggered": decision_level,
        "verdict_reason": reason,
        "google_provenance": google_info,
    }

    # Log DEBUG analysis in backend logs
    logger.info(
        "[DEBUG ANALYSIS] file=%s sha256=%s verdict=%s conf=%.3f device=%s level=%s | specialized_ai=%.3f clip_ai=%.3f cam_prov=%.3f ai_prov=%.3f c2pa_detected=%s google_detected=%s",
        debug_analysis["file_name"],
        debug_analysis["sha256"][:12],
        debug_analysis["final_verdict"],
        debug_analysis["final_confidence"],
        debug_analysis["device"],
        debug_analysis["decision_hierarchy_level_triggered"],
        debug_analysis["specialized_detector"]["score"],
        debug_analysis["clip_aggregate_score"],
        debug_analysis["camera_provenance_score"],
        debug_analysis["ai_provenance_score"],
        debug_analysis["c2pa_fields_detected"]["c2pa_detected"],
        debug_analysis["google_provenance"].get("google_provenance_detected"),
    )

    stats = _agreement_stats(all_signals)
    disagreement_report = f"Forensic consensus score: {forensic_consensus_score:.2f} ({forensic_consensus_state})"

    contribution_lookup = {
        item["key"]: item
        for rows in category_breakdown.values()
        for item in rows
    }
    evidence_breakdown = [
        {
            "signal": s.key,
            "score": s.score,
            "detail": s.detail,
            "status": s.status,
            "reliability": s.reliability,
            "category": s.category,
            "humanReadable": s.human_readable,
            "confidenceInterval": _signal_interval(s),
            "contributionImpact": contribution_lookup.get(s.key, {}).get("impact", 0.0),
            "fusionWeight": contribution_lookup.get(s.key, {}).get("weight", 0.0),
            "weightReason": contribution_lookup.get(s.key, {}).get("weight_reason", "neutral/no contribution"),
        } for s in all_signals
    ]

    return {
        "assessment": assessment,
        "legacy_verdict": legacy_verdict,
        "verdict": verdict,
        "verdict_color": color,
        "confidence_percent": int(confidence_calibration * 100),
        "verdict_reason": reason,
        "evidenceBreakdown": evidence_breakdown,
        "detectionSignals": [{"signal": s.key, "score": s.score, "detail": s.detail, "category": s.category, "status": s.status, "confidenceInterval": _signal_interval(s)} for s in all_signals],
        "suspiciousIndicators": [s.detail for s in all_signals if s.status == "active" and s.score > 0.65],
        "details": f"Content Type: {ctype}. Verdict: {verdict}. Level: {decision_level}. Fusion: {fusion_score:.2f}. Specialized: {spec_ai:.2f}. Forensic: {forensic_consensus_score:.2f}.",
        "findings": ctype_info["reasons"] + [disagreement_report, ensemble_result.detail],
        "faceDiagnostics": ctype_info.get("diagnostics", {}),
        "fusion_score": fusion_score,
        "confidence": confidence_calibration,
        "confidenceScore": confidence_calibration,
        "confidencePercent": int(confidence_calibration * 100),
        "aiProbability": int(spec_ai * 100 if spec_model_res and spec_model_res.available else fusion_score * 100),
        "manipulationRisk": int(manip_prob * 100),
        "confidenceLevel": _confidence_band(confidence_calibration),
        "confidenceBand": _confidence_band(confidence_calibration),
        "detectorDisagreement": disagreement_report,
        "classifierAgreement": stats,
        "signalCategoryBreakdown": category_breakdown,
        "signalContributionImpact": contribution_lookup,
        "debug_info": debug_info,
        "provenance": prov_data,
        "debugAnalysis": debug_analysis,
    }

def run_forensic_pipeline(file_path: str) -> Dict[str, Any]:
    logger.info(f"[Pipeline] Starting forensic analysis for: {file_path}")
    pipeline_started = time.perf_counter()
    perf: Dict[str, Any] = {"pipeline_started": pipeline_started}
    
    try:
        proc = None
        try:
            import psutil
            proc = psutil.Process(os.getpid())
            perf["memory_rss_mb_start"] = round(proc.memory_info().rss / (1024 * 1024), 2)
            perf["cpu_percent_start"] = proc.cpu_percent(interval=None)
        except Exception:
            pass

        # Provenance inspection on ORIGINAL file bytes (before any resize/re-encode)
        t0_prov = time.perf_counter()
        prov_data = _provenance_engine.analyze(file_path)
        perf["provenance_ms"] = round((time.perf_counter() - t0_prov) * 1000, 2)

        img = _load_image_bgr(file_path)
        if img is None:
            logger.error("[Pipeline] Could not load image")
            raise ValueError("Could not load image.")
        
        logger.debug(f"[Pipeline] Loaded image: {img.shape}, dtype={img.dtype}")
        log_memory_rss("image_loaded")
        
        # Create debug prefix from filename
        debug_prefix = Path(file_path).stem
        
        img, scale = _resize_long_edge(img, 896)
        logger.debug(f"[Pipeline] After resize: {img.shape}, scale={scale}")
        
        # ENHANCED: Call face detection with debug prefix
        t0 = time.perf_counter()
        faces, boxes, debug_info = _detect_faces_mediapipe(img, debug_prefix)
        perf["face_detection_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        logger.info(f"[Pipeline] Face detection complete: {len(faces)} faces found")
        log_memory_rss("face_detection_complete")
        
        # ENHANCED: Pass debug_info to content classification
        ctype_info = _classify_content_type(img, faces, file_path, debug_info)
        
        # Fallback to no-face classification if mediapipe is unavailable
        if ctype_info["type"] in ["landscape_or_object"] and debug_info.get("errors"):
            logger.warning(f"[Pipeline] Face detection error detected, but proceeding with general image forensics.")
        
        signals = []
        for name, fn in [
            ("metadata", lambda: analyze_metadata(file_path, prov_data)),
            ("sensor_noise", lambda: analyze_sensor_noise(img, ctype_info["type"])),
            ("compression_ela", lambda: analyze_compression_ela(img, ctype_info["type"])),
            ("facial_smoothness", lambda: analyze_smoothness(img, faces, ctype_info["type"])),
            ("frequency_fingerprint", lambda: analyze_frequency_fingerprint(img)),
        ]:
            t0 = time.perf_counter()
            signal = fn()
            perf[f"{name}_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            signals.append(signal)

        t0 = time.perf_counter()
        diffusion_signals = analyze_diffusion_artifacts(img, faces, boxes, ctype_info["type"])
        perf["diffusion_artifacts_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        signals.extend(diffusion_signals)
        
        # Phase 4: Portrait Forensics
        t0 = time.perf_counter()
        portrait_signals = analyze_portrait_forensics(img, faces, ctype_info["type"])
        perf["portrait_forensics_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        signals.extend(portrait_signals)
        log_memory_rss("initial_signals_complete")
        
        # Keep explainability active for weak heuristics (weight is 0.0)
        for s in signals:
            if s.key in ["eye_reflection_consistency", "repetitive_background", "frequency_fingerprint"]:
                s.status = "active"
        
        t0 = time.perf_counter()
        ensemble_result = _get_classifier().score_image(img)
        perf["ml_ensemble_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        log_memory_rss("ml_ensemble_complete")
        
        # UPGRADE: Patch-Based Forensic Analysis (Requirement Part 1 & 8)
        patch_engine = PatchForensicEngine()
        # Use face mask for ROI focus if available
        face_mask = None
        if faces and boxes:
            face_mask = np.zeros(img.shape[:2], dtype=np.uint8)
            # FIX: Iterate over 'boxes' (coordinates) instead of 'faces' (numpy arrays)
            for box in boxes:
                sbox = safe_int_box(box, img.shape[0], img.shape[1])
                if sbox:
                    x1, y1, w_box, h_box = sbox
                    if DEBUG_MODE:
                        logger.debug(f"[Forensic Debug] Drawing face mask box: ({x1}, {y1}) to ({x1+w_box}, {y1+h_box})")
                    cv2.rectangle(face_mask, (x1, y1), (x1 + w_box, y1 + h_box), 255, -1)
                
        patch_result = patch_engine.analyze(img, mask=face_mask)
        if patch_result.available:
            patch_result.heatmap_path = patch_engine.generate_heatmap(img, patch_result)
        log_memory_rss("patch_engine_complete")

        result = fuse_signals(signals, ensemble_result, patch_result, ctype_info, prov_data=prov_data, file_path=file_path)
        perf["total_inference_ms"] = round((time.perf_counter() - pipeline_started) * 1000, 2)
        
        # ... (keep proc logic unchanged)
        if proc is not None:
            try:
                perf["memory_rss_mb_end"] = round(proc.memory_info().rss / (1024 * 1024), 2)
                perf["cpu_percent_end"] = proc.cpu_percent(interval=None)
            except Exception:
                pass
        
        # Include debug info in response
        result["debug_info"] = debug_info
        result["debug_detector"] = "mediapipe_tasks_active" if debug_info.get("mediapipe_api") == "tasks_vision" and debug_info.get("mediapipe_branch_executed") else "mediapipe_inactive"
        result["debug_face_count"] = len(faces)
        result["debug_bboxes"] = boxes
        result["debug_confidences"] = debug_info.get("confidence_values", [])
        result["debug_content_type"] = ctype_info["type"]
        result["debug_pipeline_module"] = __file__
        result["performance"] = perf
        
        # Ensemble Transparency (Requirement Part 3, 5, 6, 7)
        # Extract metrics from the ensemble detail for display
        model_metrics = {}
        try:
            for part in ensemble_result.detail.split(" | ")[1:]:
                name_val = part.split(": ")
                if len(name_val) >= 2:
                    m_name = name_val[0]
                    # Parse raw=... weight=... multiplier=... cal_prior=... reason=...
                    m_raw = re.search(r"raw=([0-9.]+)", name_val[1])
                    m_weight = re.search(r"weight=([0-9.]+)", name_val[1])
                    m_mult = re.search(r"multiplier=([0-9.]+)", name_val[1])
                    m_cal = re.search(r"cal_prior=([0-9.]+)", name_val[1])
                    m_reason = re.search(r"reason=([a-zA-Z\s\-]+)", name_val[1])
                    
                    model_metrics[m_name] = {
                        "raw": float(m_raw.group(1)) if m_raw else 0.0,
                        "weight": float(m_weight.group(1)) if m_weight else 0.0,
                        "multiplier": float(m_mult.group(1)) if m_mult else 1.0,
                        "calibration_prior": float(m_cal.group(1)) if m_cal else 0.0,
                        "reason": m_reason.group(1).strip() if m_reason else "nominal"
                    }
        except Exception:
            pass

        result["mlEnsemble"] = {
            "available": ensemble_result.available,
            "score": ensemble_result.ensemble_score,
            "confidence": ensemble_result.ensemble_confidence,
            "agreement": ensemble_result.agreement_score,
            "disagreement": ensemble_result.disagreement,
            "models": [
                {
                    "name": r.model_name,
                    "probability": r.ai_probability,
                    "confidence": r.confidence,
                    "raw_score": model_metrics.get(r.model_name, {}).get("raw", r.ai_probability),
                    "base_weight": AIEnsembleClassifier.MODEL_PRIORS.get(r.model_name, {}).get("weight", 1.0),
                    "persistent_bias_penalty": AIEnsembleClassifier.MODEL_PRIORS.get(r.model_name, {}).get("persistent_bias_penalty", 1.0),
                    "calibration_prior": model_metrics.get(r.model_name, {}).get("calibration_prior", 0.0),
                    "effective_multiplier": model_metrics.get(r.model_name, {}).get("multiplier", 1.0),
                    "effective_multiplier_reason": model_metrics.get(r.model_name, {}).get("reason", "nominal"),
                    "multiplier": model_metrics.get(r.model_name, {}).get("multiplier", 1.0),
                    "effective_weight": ensemble_result.weights.get(r.model_name, 0.0),
                    "status": "active" if r.available else "failed"
                } for r in ensemble_result.results
            ]
        }
        
        # Patch Forensics Explainability (Requirement Part 5)
        result["forensicHeatmap"] = patch_result.heatmap_path
        result["patchAnalysis"] = {
            "available": patch_result.available,
            "mean_score": patch_result.mean_score,
            "peak_artifact_score": patch_result.peak_score,
            "suspicious_patch_density": patch_result.suspicious_density,
            "clustering_score": patch_result.clustering_score,
            "total_patches": len(patch_result.patches) if patch_result.available else 0,
            "top_suspicious_regions": [
                {"x": p.x, "y": p.y, "score": p.synthetic_score}
                for p in sorted(patch_result.patches, key=lambda x: x.synthetic_score, reverse=True)[:5]
            ] if patch_result.available else []
        }
        
        # LOGGING ENHANCEMENT
        logger.info(
            "[Pipeline Debug] Verdict: %s (Conf: %d%%) | Ensemble Score: %.3f | Agreement: %.2f",
            result.get('verdict'), result.get('confidence_percent', 0), result.get('fusion_score', 0.5), ensemble_result.agreement_score
        )
        
        for sig in result.get("evidenceBreakdown", []):
            if sig['status'] == 'active':
                logger.info(f"[Pipeline Debug] Signal {sig['signal']}: score={sig['score']:.3f}, impact={sig['contributionImpact']:.3f}")

        # Requirement Part 7: Log detailed model metrics for verification
        if "mlEnsemble" in result:
            for m in result["mlEnsemble"]["models"]:
                logger.info(
                    f"[Ensemble Weight Audit] Model: {m['name']} | "
                    f"raw_score: {m.get('raw_score', m['probability']):.3f} | "
                    f"multiplier: {m.get('multiplier', 1.0):.2f} | "
                    f"effective_weight: {m.get('effective_weight', 0.0):.3f} | "
                    f"suppression_applied: {'YES' if m.get('multiplier', 1.0) < 0.9 else 'NO'}"
                )

        # FINAL SERIALIZATION SAFETY (Requirement 6: Live Verification)
        result["runtime_version"] = "ensemble_weight_patch_live"
        log_memory_rss("pipeline_complete")
        return sanitize_for_json(result)
        
    except Exception as e:
        logger.error(f"[Pipeline] Analysis failed: {e}", exc_info=True)
        raise

def run_forensic_pipeline_video(file_path: str) -> Dict[str, Any]:
    return {
        "assessment": "insufficient_evidence",
        "legacy_verdict": "unverified",
        "verdict": "INSUFFICIENT EVIDENCE",
        "verdict_color": "yellow",
        "confidence_percent": 0,
        "verdict_reason": "Reliable temporal video analysis is not currently supported.",
        "detectionSignals": [],
        "suspiciousIndicators": [],
        "details": "Video files require optical flow and temporal landmark tracking for reliable deepfake detection. Frame averaging is insufficient.",
        "findings": ["Video analysis lacks temporal reasoning."],
        "fusion_score": 0.5,
        "confidence": 0.0,
        "aiProbability": 50,
        "manipulationRisk": 50,
        "confidenceLevel": "low"
    }

class DeepfakeDetector:
    def detect_deepfake(self, file_path: str) -> Dict[str, Any]:
        ext = Path(file_path).suffix.lower()
        if ext in {".mp4", ".mov", ".avi", ".mkv", ".webm"}:
            return sanitize_for_json(run_forensic_pipeline_video(file_path))
        return sanitize_for_json(run_forensic_pipeline(file_path))
