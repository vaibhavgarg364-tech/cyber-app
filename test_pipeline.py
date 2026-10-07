import os
import sys
import json

from backend.routes.deepfake_pipeline import run_forensic_pipeline

def test_images():
    test_dirs = [
        "tests/media/ai_google",
        "tests/media/ai_other",
        "tests/media/edited_real",
        "tests/media/real_camera",
        "tests/media/social_export"
    ]
    
    results = {}
    
    for td in test_dirs:
        print(f"\n--- Testing directory: {td} ---")
        if not os.path.exists(td):
            print(f"Directory {td} not found.")
            continue
        
        for f in os.listdir(td):
            if f.lower().endswith(('.png', '.jpg', '.jpeg', '.webp')):
                file_path = os.path.join(td, f)
                try:
                    # Mock an upload file name for provenance parsing if needed
                    res = run_forensic_pipeline(file_path)
                    
                    verdict = res.get('verdict', 'UNKNOWN')
                    conf = res.get('confidence_percent', 0)
                    ai_prob = res.get('aiProbability', -1)
                    
                    print(f"[{verdict}] (Conf: {conf}%, AI Prob: {ai_prob}%) - {f}")
                    results[file_path] = res
                except Exception as e:
                    print(f"[ERROR] {f}: {e}")

if __name__ == "__main__":
    test_images()
