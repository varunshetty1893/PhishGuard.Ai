import sys
import os
from pathlib import Path

# Set up backend import path portably
BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))
os.chdir(str(BACKEND_DIR))

MODEL_PATH = BACKEND_DIR / "app" / "ml" / "artifacts" / "phishguard_rf_model.joblib"

# Check for Git LFS pointer
if MODEL_PATH.exists():
    with open(MODEL_PATH, "rb") as fh:
        header = fh.read(30)
    if header.startswith(b"version https://git-lfs"):
        raise RuntimeError("Model is a Git LFS pointer — run `git lfs pull`.")

from app.services.ml_inference import MLInferenceService
MLInferenceService.load()

test_urls = [
    "https://google.com",
    "https://www.google.com",
    "https://wikipedia.org/wiki/Computer_science",
    "https://github.com/microsoft/vscode",
    "https://www.microsoft.com",
    "http://login.paypal.com.account-verify.xyz/signin",
    "http://125.42.15.201:43234/bin.sh",
    "https://maildinshaakckjnw54.firebaseapp.com/",
    "https://msc-b00k-0ffice365.firebaseapp.com/"
]

meta = MLInferenceService.get_metadata()
total_samples = (
    meta.get("training_samples", 0)
    + meta.get("validation_samples", 0)
    + meta.get("test_samples", 0)
)
print("Model version:", meta.get("model_version"))
print("Total training samples:", meta.get("training_samples", meta.get("total_samples")))
print("Total samples (train+val+test):", total_samples)
print("Decision threshold:", meta.get("decision_threshold"))

for u in test_urls:
    res = MLInferenceService.predict(u)
    cls = res["predicted_class"]
    lvl = res["risk_level"]
    scr = res["model_score"] * 100
    print(f"{u:<52} -> {cls:<12} | {lvl:<11} ({scr:.1f}%)")
