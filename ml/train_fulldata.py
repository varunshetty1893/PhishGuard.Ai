"""
PhishGuard AI - Full Data Retrain v3.0
Uses ALL available labeled URL data (~3.37 lakh URLs)
"""
import os, sys, json, time, hashlib, shutil, warnings
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from datetime import datetime, timezone
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

warnings.filterwarnings("ignore")

ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = ROOT / "dataset"
ML_DIR = ROOT / "ml"
DATA_DIR = ML_DIR / "data"
ARTIFACTS_DIR = ML_DIR / "artifacts"
REPORTS_DIR = ML_DIR / "reports"
BACKEND_ARTIFACTS = ROOT / "backend" / "app" / "ml" / "artifacts"

for d in [DATA_DIR, ARTIFACTS_DIR, REPORTS_DIR, BACKEND_ARTIFACTS]:
    d.mkdir(parents=True, exist_ok=True)

SUSPICIOUS_KEYWORDS = [
    "login","signin","verify","secure","update","confirm","bank","paypal",
    "account","password","credential","suspend","limited","webscr","logon",
    "alert","security","validation","wallet","support","helpdesk",
]

FEATURE_NAMES = [
    "url_length","hostname_length","path_length","count_dots","count_hyphens",
    "count_at","count_question","count_equal","count_slash","count_digits",
    "count_subdomains","has_ip","is_https","has_suspicious_keywords",
    "digit_ratio","special_char_ratio",
]

def _is_ip(h):
    import re
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", h or ""))

def extract_features(url):
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        hostname = p.hostname or ""
        path = p.path or ""
        parts = [x for x in hostname.split(".") if x]
        sub_count = max(0, len(parts) - 2)
        total_len = len(url)
        digits = sum(c.isdigit() for c in url)
        specials = sum(not c.isalnum() and c not in "/:." for c in url)
        return [
            total_len, len(hostname), len(path),
            url.count("."), url.count("-"), url.count("@"),
            url.count("?"), url.count("="), url.count("/"),
            digits, sub_count,
            1 if _is_ip(hostname) else 0,
            1 if p.scheme == "https" else 0,
            1 if any(k in url.lower() for k in SUSPICIOUS_KEYWORDS) else 0,
            digits / max(total_len, 1),
            specials / max(total_len, 1),
        ]
    except:
        return [0] * 16

def main():
    start = time.time()
    print("=" * 70)
    print("  PhishGuard AI - Full Data Retrain v3.0")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    frames = []

    p1 = DATASET_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv"
    if p1.exists():
        df1 = pd.read_csv(p1, usecols=["URL","label"], low_memory=False)
        df1 = df1.rename(columns={"URL":"url","label":"src_label"})
        df1["label"] = df1["src_label"].apply(lambda x: 1 if x==0 else 0)
        df1 = df1[["url","label"]]
        df1["source"] = "PhiUSIIL"
        frames.append(df1)
        print(f"  PhiUSIIL:               {len(df1):>7,} rows  (Phish={( df1['label']==1).sum():,}, Legit={(df1['label']==0).sum():,})")

    p2 = DATASET_DIR / "url_features_extracted1.csv"
    if p2.exists():
        df2 = pd.read_csv(p2, usecols=["URL","ClassLabel"], low_memory=False)
        df2 = df2.rename(columns={"URL":"url","ClassLabel":"src_label"})
        df2["label"] = df2["src_label"].apply(lambda x: 1 if x==0 else 0)
        df2 = df2[["url","label"]]
        df2["source"] = "URLFeatures"
        frames.append(df2)
        print(f"  url_features_extracted1:{len(df2):>7,} rows  (Phish={(df2['label']==1).sum():,}, Legit={(df2['label']==0).sum():,})")

    if not frames:
        print("ERROR: No dataset files found.")
        sys.exit(1)

    df = pd.concat(frames, ignore_index=True)
    print(f"\n  Combined total:          {len(df):>7,}")

    print("\n[2/7] Cleaning and deduplicating ...")
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"].str.startswith("http")].copy()
    before = len(df)
    df = df.drop_duplicates(subset=["url"])
    print(f"  Removed {before - len(df):,} duplicates. Unique: {len(df):,}")
    print(f"  Phishing: {(df['label']==1).sum():,}  |  Legit: {(df['label']==0).sum():,}")

    print("\n  Applying benign path debiasing ...")
    benign_paths = ["/about","/contact","/home","/services","/products","/blog",
                    "/news","/faq","/team","/privacy","/terms","/support",
                    "/careers","/gallery","/resources","/docs","/help",
                    "/shop","/portfolio","/events"]
    rng = np.random.default_rng(42)
    legit_mask = df["label"] == 0
    bare_mask = df["url"].str.rstrip("/").apply(lambda u: len(u.split("//")[-1].split("/")) <= 1)
    target_idx = df[legit_mask & bare_mask].index
    sample_size = int(len(target_idx) * 0.30)
    sampled_idx = rng.choice(target_idx, size=sample_size, replace=False)
    paths_chosen = rng.choice(benign_paths, size=sample_size)
    df.loc[sampled_idx, "url"] = df.loc[sampled_idx, "url"].str.rstrip("/").values + paths_chosen
    print(f"  Debiased {sample_size:,} bare legit URLs")

    print(f"\n[3/7] Extracting features from {len(df):,} URLs ...")
    t0 = time.time()
    urls = df["url"].tolist()
    features = []
    checkpoint = max(1, len(urls) // 10)
    for i, url in enumerate(urls):
        features.append(extract_features(url))
        if (i+1) % checkpoint == 0:
            pct = (i+1)/len(urls)*100
            print(f"  {pct:5.1f}%  ({i+1:,}/{len(urls):,})  [{time.time()-t0:.0f}s]")
    X = np.array(features, dtype=np.float32)
    y = df["label"].values
    print(f"  Done in {time.time()-t0:.1f}s. Shape: {X.shape}")

    print("\n  Saving dataset CSV ...")
    df[["url","label","source"]].to_csv(DATA_DIR / "dataset.csv", index=False)
    print(f"  Saved ml/data/dataset.csv ({len(df):,} rows)")

    print("\n[4/7] Train/test split 80/20 stratified ...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, stratify=y, random_state=42)
    print(f"  Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    print("\n[5/7] 5-fold cross-validation ...")
    clf_cv = RandomForestClassifier(n_estimators=150, max_depth=20, min_samples_leaf=2,
                                    max_features="sqrt", class_weight="balanced",
                                    random_state=42, n_jobs=-1)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv = cross_validate(clf_cv, X_train, y_train, cv=skf,
                        scoring=["accuracy","f1","roc_auc"], n_jobs=-1)
    cv_acc = cv["test_accuracy"].mean()
    cv_f1  = cv["test_f1"].mean()
    cv_auc = cv["test_roc_auc"].mean()
    print(f"  CV Accuracy: {cv_acc:.6f} +/- {cv['test_accuracy'].std():.6f}")
    print(f"  CV F1:       {cv_f1:.6f} +/- {cv['test_f1'].std():.6f}")
    print(f"  CV AUC:      {cv_auc:.6f} +/- {cv['test_roc_auc'].std():.6f}")

    print("\n[6/7] Training final model ...")
    clf = RandomForestClassifier(n_estimators=150, max_depth=20, min_samples_leaf=2,
                                 max_features="sqrt", class_weight="balanced",
                                 random_state=42, n_jobs=-1)
    t_tr = time.time()
    clf.fit(X_train, y_train)
    print(f"  Trained in {time.time()-t_tr:.1f}s")

    print("\n[7/7] Evaluating on holdout test set ...")
    y_pred  = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:,1]
    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec  = recall_score(y_test, y_pred)
    f1   = f1_score(y_test, y_pred)
    auc  = roc_auc_score(y_test, y_proba)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    print(f"\n  Accuracy:  {acc:.6f}  ({acc*100:.2f}%)")
    print(f"  Precision: {prec:.6f}  ({prec*100:.2f}%)")
    print(f"  Recall:    {rec:.6f}  ({rec*100:.2f}%)")
    print(f"  F1-Score:  {f1:.6f}  ({f1*100:.2f}%)")
    print(f"  ROC-AUC:   {auc:.6f}  ({auc*100:.2f}%)")
    print(f"  Confusion Matrix: TN={tn:,} FP={fp:,} FN={fn:,} TP={tp:,}")

    importances = dict(zip(FEATURE_NAMES, clf.feature_importances_.tolist()))

    print("\n  Saving model ...")
    model_path = ARTIFACTS_DIR / "phishguard_rf_model.joblib"
    joblib.dump(clf, model_path, compress=3)
    sha256 = hashlib.sha256(model_path.read_bytes()).hexdigest()
    print(f"  Saved {model_path} ({model_path.stat().st_size/1024/1024:.1f} MB)")
    print(f"  SHA256: {sha256}")

    metadata = {
        "model_name": "RandomForestClassifier",
        "version": "3.0.0",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "training_duration_seconds": round(time.time()-start, 1),
        "total_samples": len(df),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "cv_folds": 5,
        "cv_accuracy": round(cv_acc, 6),
        "cv_f1_score": round(cv_f1, 6),
        "cv_roc_auc": round(cv_auc, 6),
        "accuracy": round(acc, 6),
        "precision": round(prec, 6),
        "recall": round(rec, 6),
        "f1_score": round(f1, 6),
        "roc_auc": round(auc, 6),
        "confusion_matrix": {"tn":int(tn),"fp":int(fp),"fn":int(fn),"tp":int(tp)},
        "hyperparameters": {
            "n_estimators":150,"max_depth":20,"min_samples_leaf":2,
            "max_features":"sqrt","class_weight":"balanced","random_state":42
        },
        "feature_names": FEATURE_NAMES,
        "feature_importances": {k: round(v,6) for k,v in importances.items()},
        "label_mapping": {"0":"Legitimate","1":"Phishing"},
        "sha256_model": sha256,
        "sources": ["PhiUSIIL_Phishing_URL_Dataset","url_features_extracted1"],
    }
    meta_path = ARTIFACTS_DIR / "model_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    shutil.copy2(model_path, BACKEND_ARTIFACTS / "phishguard_rf_model.joblib")
    shutil.copy2(meta_path,  BACKEND_ARTIFACTS / "model_metadata.json")
    print("  Mirrored to backend/app/ml/artifacts/")

    # Save report
    sorted_imp = sorted(importances.items(), key=lambda x: x[1], reverse=True)
    report = f"""# PhishGuard AI - Model Evaluation Report v3.0

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Dataset
- Total unique URLs used: {len(df):,}
- Sources: PhiUSIIL + URLFeatures (all available data)
- Training set: {len(X_train):,}
- Test set:     {len(X_test):,}

## 5-Fold Cross-Validation (on training set)
| Metric   | Mean    | Std     |
|----------|---------|---------|
| Accuracy | {cv_acc:.4f} | {cv['test_accuracy'].std():.4f} |
| F1-Score | {cv_f1:.4f}  | {cv['test_f1'].std():.4f}  |
| ROC-AUC  | {cv_auc:.4f} | {cv['test_roc_auc'].std():.4f} |

## Holdout Test Metrics
| Metric    | Value              |
|-----------|--------------------|
| Accuracy  | {acc:.6f} ({acc*100:.2f}%) |
| Precision | {prec:.6f} ({prec*100:.2f}%) |
| Recall    | {rec:.6f} ({rec*100:.2f}%) |
| F1-Score  | {f1:.6f} ({f1*100:.2f}%) |
| ROC-AUC   | {auc:.6f} ({auc*100:.2f}%) |

## Confusion Matrix
|              | Pred Legit | Pred Phish |
|--------------|------------|------------|
| Actual Legit | TN={tn:,}  | FP={fp:,}  |
| Actual Phish | FN={fn:,}  | TP={tp:,}  |

## Feature Importances (Top 16)
| Feature | Importance |
|---------|-----------|
""" + "".join(f"| {k} | {v:.4f} |\n" for k, v in sorted_imp)

    with open(REPORTS_DIR / "model_evaluation_report.md", "w") as f:
        f.write(report)

    print(f"\n{'='*70}")
    print(f"  DONE in {(time.time()-start)/60:.1f} minutes")
    print(f"  Model v3.0: {len(df):,} samples | Accuracy {acc*100:.2f}% | AUC {auc*100:.2f}%")
    print(f"{'='*70}")

if __name__ == "__main__":
    main()
