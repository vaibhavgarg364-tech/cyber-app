import os
import sys
import time
import logging
from pathlib import Path
from typing import List, Dict, Any

# Add backend to path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from routes.deepfake_pipeline import DeepfakeDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("veyron-benchmark")

def run_benchmark(test_dir: str):
    detector = DeepfakeDetector()
    results = []
    
    categories = {
        "real_selfies": "REAL",
        "dslr_portraits": "REAL",
        "whatsapp_compressed": "REAL",
        "screenshots": "REAL",
        "midjourney": "FAKE",
        "stable_diffusion": "FAKE",
        "flux": "FAKE",
        "dalle": "FAKE"
    }
    
    stats = {cat: {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "inconclusive": 0, "total": 0} for cat in categories}
    
    test_path = Path(test_dir)
    if not test_path.exists():
        logger.error(f"Test directory {test_dir} does not exist.")
        # Create a mock summary if no dir exists to show the logic
        print("\n=== DEEPFAKE PIPELINE BENCHMARK SUMMARY (MOCK) ===")
        print("Note: Run with actual images to see real stats.")
        return

    for cat_dir, expected in categories.items():
        cat_path = test_path / cat_dir
        if not cat_path.exists():
            continue
            
        for img_path in cat_path.glob("*"):
            if img_path.suffix.lower() not in [".jpg", ".jpeg", ".png", ".webp"]:
                continue
                
            try:
                start_t = time.perf_counter()
                res = detector.detect_deepfake(str(img_path))
                elapsed = time.perf_counter() - start_t
                
                verdict = res.get("assessment", "inconclusive")
                
                stats[cat_dir]["total"] += 1
                
                if verdict == "inconclusive":
                    stats[cat_dir]["inconclusive"] += 1
                elif expected == "REAL":
                    if verdict == "likely_authentic":
                        stats[cat_dir]["tn"] += 1
                    else:
                        stats[cat_dir]["fp"] += 1
                elif expected == "FAKE":
                    if verdict == "likely_ai_generated":
                        stats[cat_dir]["tp"] += 1
                    else:
                        stats[cat_dir]["fn"] += 1
                        
                ensemble = res.get("mlEnsemble", {})
                agreement = ensemble.get("agreement", 0.0)
                
                results.append({
                    "path": str(img_path),
                    "category": cat_dir,
                    "expected": expected,
                    "verdict": verdict,
                    "score": res.get("fusion_score"),
                    "confidence": res.get("confidence"),
                    "agreement": agreement,
                    "ms": round(elapsed * 1000, 2)
                })
                
            except Exception as e:
                logger.error(f"Failed to process {img_path}: {e}")

    # Print Summary
    print("\n" + "="*60)
    print(" DEEPFAKE PIPELINE BENCHMARK SUMMARY")
    print("="*60)
    print(f"{'Category':<20} | {'Total':<5} | {'TN/TP':<6} | {'FP/FN':<6} | {'INC':<5} | {'Recall':<6} | {'Prec'}")
    print("-" * 75)
    
    grand_total = {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "inc": 0, "total": 0}
    
    for cat, s in stats.items():
        if s["total"] == 0: continue
        
        expected = categories[cat]
        if expected == "REAL":
            correct = s["tn"]
            errors = s["fp"]
        else:
            correct = s["tp"]
            errors = s["fn"]
            
        recall = correct / (correct + errors) if (correct + errors) > 0 else 0
        # Precision for 'FAKE' detection
        prec = s["tp"] / (s["tp"] + s["fp"]) if (s["tp"] + s["fp"]) > 0 else 0
        
        print(f"{cat:<20} | {s['total']:<5} | {correct:<6} | {errors:<6} | {s['inconclusive']:<5} | {recall:>6.1%} | {prec:>6.1%}")
        
        grand_total["total"] += s["total"]
        grand_total["tp"] += s["tp"]
        grand_total["tn"] += s["tn"]
        grand_total["fp"] += s["fp"]
        grand_total["fn"] += s["fn"]
        grand_total["inc"] += s["inconclusive"]

    print("-" * 75)
    gt = grand_total
    all_correct = gt["tp"] + gt["tn"]
    all_wrong = gt["fp"] + gt["fn"]
    overall_acc = all_correct / (all_correct + all_wrong) if (all_correct + all_wrong) > 0 else 0
    
    print(f"{'OVERALL':<20} | {gt['total']:<5} | {all_correct:<6} | {all_wrong:<6} | {gt['inc']:<5} | Acc: {overall_acc:>6.1%}")
    
    # FPR and FNR
    fpr = gt["fp"] / (gt["tn"] + gt["fp"]) if (gt["tn"] + gt["fp"]) > 0 else 0
    fnr = gt["fn"] / (gt["tp"] + gt["fn"]) if (gt["tp"] + gt["fn"]) > 0 else 0
    
    print("\nMETRICS:")
    print(f"False Positive Rate (FPR): {fpr:.2%}")
    print(f"False Negative Rate (FNR): {fnr:.2%}")
    print(f"Inconclusive Rate: {gt['inc'] / gt['total'] if gt['total'] > 0 else 0:.2%}")
    print("="*60 + "\n")

if __name__ == "__main__":
    test_dir = sys.argv[1] if len(sys.argv) > 1 else "test_images"
    run_benchmark(test_dir)
