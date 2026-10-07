"""
Rigorous Benchmark Evaluation Script for Veyron Media Authentication Pipeline.
Audits and benchmarks detection across:
- tests/media/real_camera/
- tests/media/ai_google/
- tests/media/ai_other/
- tests/media/edited_real/
- tests/media/social_export/

Calculates:
Accuracy, Precision, Recall, F1, False Positive Rate (FPR), False Negative Rate (FNR),
Confusion Matrix, and isolates critical failure cases (REAL->AI and AI->REAL).
"""

import sys
import os
from pathlib import Path
import time
from typing import Dict, Any, List

# Add backend directory to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Ensure device and huggingface cache environment are loaded
os.environ.setdefault("HF_HOME", "D:\\AI_CACHE\\huggingface")

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from routes.deepfake_pipeline import DeepfakeDetector

VALID_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}

def evaluate_media_pipeline():
    detector = DeepfakeDetector()
    media_root = PROJECT_ROOT / "tests" / "media"
    
    categories = [
        ("real_camera", "REAL", "Authentic camera captures (Phone & DSLR)"),
        ("ai_google", "AI", "Google Gemini / Imagen generated media"),
        ("ai_other", "AI", "Midjourney / SDXL / DALL-E / Flux AI media"),
        ("edited_real", "MANIPULATED", "Spliced / manipulated photographs"),
        ("social_export", "REAL_EXPORT", "Compressed / stripped social exports (WhatsApp/Web)"),
    ]

    print("\n" + "="*110)
    print(" VEYRON MEDIA AUTHENTICATION BENCHMARK SUITE")
    print("="*110)

    results = []
    
    for folder_name, expected_type, desc in categories:
        folder_path = media_root / folder_name
        if not folder_path.exists():
            print(f"Warning: Directory not found: {folder_path}")
            continue

        files = sorted([p for p in folder_path.iterdir() if p.suffix.lower() in VALID_EXTENSIONS])
        print(f"\n[*] [{folder_name}] - {desc} ({len(files)} files)")

        for fpath in files:
            t0 = time.time()
            try:
                res = detector.detect_deepfake(str(fpath))
            except Exception as e:
                print(f"  [ERROR] Error evaluating {fpath.name}: {e}")
                continue
            elapsed = time.time() - t0

            debug = res.get("debugAnalysis", {})
            verdict = res.get("verdict", "UNCERTAIN")
            conf_pct = res.get("confidence_percent", int(res.get("confidence", 0) * 100))
            
            # Extract disaggregated scores
            c2pa_status = "DETECTED" if debug.get("c2pa_fields_detected", {}).get("c2pa_detected") else "NONE"
            exif_count = len(debug.get("exif_fields_detected", []))
            exif_status = f"{exif_count} tags" if exif_count > 0 else "STRIPPED"
            if debug.get("camera_manufacturer") or debug.get("camera_model"):
                cam_str = f"{debug.get('camera_manufacturer') or ''} {debug.get('camera_model') or ''}".strip()
                provenance_str = f"Camera: {cam_str}"
            elif debug.get("google_provenance", {}).get("google_provenance_detected"):
                provenance_str = "Google AI Provenance"
            elif debug.get("generator_tool"):
                provenance_str = f"Generator: {debug.get('generator_tool')}"
            else:
                provenance_str = "Neutral / Stripped"

            spec_score = debug.get("specialized_detector", {}).get("score", 0.5)
            clip_avail = debug.get("clip_available", False)
            clip_score = debug.get("clip_aggregate_score", 0.0) if clip_avail else "UNAVAILABLE"
            forensic_score = debug.get("forensic_aggregate_score", 0.5)
            fusion_score = debug.get("final_fusion_score", 0.5)

            results.append({
                "filename": fpath.name,
                "folder": folder_name,
                "expected": expected_type,
                "provenance": provenance_str,
                "c2pa": c2pa_status,
                "exif": exif_status,
                "spec_score": spec_score,
                "clip_score": clip_score,
                "forensic_score": forensic_score,
                "fusion_score": fusion_score,
                "prediction": verdict,
                "confidence": conf_pct,
                "elapsed_ms": int(elapsed * 1000)
            })

    # --- PRINT DETAILED TABLE ---
    print("\n" + "="*145)
    print(f"{'Filename':<28} | {'Expected':<10} | {'Provenance':<24} | {'C2PA':<6} | {'EXIF':<9} | {'Spec ML':<7} | {'CLIP':<7} | {'Forensic':<8} | {'Prediction':<20} | {'Conf':<5}")
    print("="*145)

    for r in results:
        clip_display = f"{r['clip_score']:.3f}" if isinstance(r['clip_score'], (int, float)) else "UNAVAIL"
        print(f"{r['filename'][:28]:<28} | {r['expected']:<10} | {r['provenance'][:24]:<24} | {r['c2pa']:<6} | {r['exif']:<9} | {r['spec_score']:<7.3f} | {clip_display:<7} | {r['forensic_score']:<8.3f} | {r['prediction']:<20} | {r['confidence']}%")

    print("="*145)

    # --- METRICS CALCULATION ---
    # Binary classification definitions:
    # Target: AI Detection
    # Positive class (AI): AI_GENERATED, LIKELY_AI
    # Negative class (REAL): AUTHENTIC_PROVENANCE, LIKELY_AUTHENTIC
    # Uncertain: UNCERTAIN, MANIPULATED (for binary camera vs AI)
    
    tp = 0 # Expected AI -> Predicted AI
    fp = 0 # Expected REAL -> Predicted AI (CRITICAL FAILURE 1)
    tn = 0 # Expected REAL -> Predicted REAL
    fn = 0 # Expected AI -> Predicted REAL (CRITICAL FAILURE 2)
    uncertain_real = 0
    uncertain_ai = 0

    critical_real_to_ai = []
    critical_ai_to_real = []

    for r in results:
        exp = r["expected"]
        pred = r["prediction"]

        is_pred_ai = pred in {"AI_GENERATED", "LIKELY_AI"}
        is_pred_real = pred in {"AUTHENTIC_PROVENANCE", "LIKELY_AUTHENTIC"}
        is_pred_uncertain = pred in {"UNCERTAIN", "MANIPULATED"}

        if exp == "AI":
            if is_pred_ai:
                tp += 1
            elif is_pred_real:
                fn += 1
                critical_ai_to_real.append(r)
            else:
                uncertain_ai += 1
        elif exp in {"REAL", "REAL_EXPORT"}:
            if is_pred_real:
                tn += 1
            elif is_pred_ai:
                fp += 1
                critical_real_to_ai.append(r)
            else:
                uncertain_real += 1

    decisive_total = tp + fp + tn + fn
    total_samples = len(results)

    accuracy = (tp + tn) / decisive_total if decisive_total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    print("\n" + "="*50)
    print(" BENCHMARK PERFORMANCE METRICS")
    print("="*50)
    print(f"Total Dataset Samples:          {total_samples}")
    print(f"Decisive Evaluations:           {decisive_total}")
    print(f"Uncertain / Manual Review:      {uncertain_real + uncertain_ai}")
    print(f"--------------------------------------------------")
    print(f"Accuracy (Decisive Decisions):  {accuracy * 100:.2f}%")
    print(f"Precision (AI Detection):       {precision * 100:.2f}%")
    print(f"Recall (AI Detection):          {recall * 100:.2f}%")
    print(f"F1-Score:                       {f1 * 100:.2f}%")
    print(f"False Positive Rate (FPR):      {fpr * 100:.2f}%")
    print(f"False Negative Rate (FNR):      {fnr * 100:.2f}%")
    print("--------------------------------------------------")
    print("Confusion Matrix:")
    print(f"  True Positives (AI -> AI):     {tp}")
    print(f"  False Positives (REAL -> AI):  {fp}  [CRITICAL FAILURE 1]")
    print(f"  True Negatives (REAL -> REAL): {tn}")
    print(f"  False Negatives (AI -> REAL):  {fn}  [CRITICAL FAILURE 2]")
    print(f"  Uncertain Cases:               {uncertain_real + uncertain_ai} (Real: {uncertain_real}, AI: {uncertain_ai})")
    print("="*50)

    print("\nCRITICAL FAILURE AUDIT:")
    print(f"1. REAL CAMERA -> predicted AI (Count: {len(critical_real_to_ai)}):")
    if critical_real_to_ai:
        for c in critical_real_to_ai:
            print(f"   [!] {c['filename']} (Spec: {c['spec_score']:.3f}, Forensic: {c['forensic_score']:.3f}, Pred: {c['prediction']})")
    else:
        print("   [OK] NONE! Zero false positives observed on authentic camera captures.")

    print(f"\n2. AI GENERATED -> predicted REAL (Count: {len(critical_ai_to_real)}):")
    if critical_ai_to_real:
        for c in critical_ai_to_real:
            print(f"   [!] {c['filename']} (Spec: {c['spec_score']:.3f}, Forensic: {c['forensic_score']:.3f}, Pred: {c['prediction']})")
    else:
        print("   [OK] NONE! Zero AI-generated images slipped through as Authentic.")

    print("\n" + "="*50)
    print("BENCHMARK COMPLETED SUCCESSFULLY")
    print("="*50 + "\n")

    return {
        "total": total_samples,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr
    }

if __name__ == "__main__":
    evaluate_media_pipeline()
