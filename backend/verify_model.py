import sys, os
sys.path.insert(0, r"D:\git projects\phishing url detector\backend")
os.chdir(r"D:\git projects\phishing url detector\backend")

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
print("Model version:", meta.get("model_version"))
print("Total training samples:", meta.get("total_samples"))

for u in test_urls:
    res = MLInferenceService.predict(u)
    cls = res["predicted_class"]
    lvl = res["risk_level"]
    scr = res["model_score"] * 100
    print(f"{u:<52} -> {cls:<12} | {lvl:<11} ({scr:.1f}%)")
