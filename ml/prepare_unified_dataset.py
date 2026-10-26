"""
PhishGuard AI - Unified Dataset Preparation Pipeline (v2.1)
============================================================
Integrates PhiUSIIL and LegitPhish datasets into a clean, balanced,
and debiased training corpus for robust ML model training.

Key Enhancements in v2.1:
  - Canonical label mapping: 1 = Phishing, 0 = Legitimate
  - Deduplication across datasets and conflict resolution
  - Real-world distribution debiasing:
      * Raw Alexa crawl datasets present legitimate domains strictly as 'https://www.<domain>/'
        with 0-length paths, creating spurious correlation where decision trees learn that any
        subpath or apex domain is phishing.
      * We apply realistic benign URL surface normalization:
          - Apex domain variation (35% stripped 'www.')
          - Common benign path augmentation (40% realistic subpaths)
          - Protocol variation (5% http)
  - Balanced stratified sampling: 30,000 legitimate + 30,000 phishing URLs (60,000 total)
  - Exact 16-feature lexical extraction saved to ml/data/dataset.csv
"""

import os, sys, random, logging
from datetime import datetime, timezone
from urllib.parse import urlparse
import pandas as pd
import numpy as np

ML_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ML_DIR)
from feature_extraction import FEATURE_NAMES, extract_url_features, features_to_vector

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("phishguard.prepare")

DATASET_DIR   = os.path.join(os.path.dirname(ML_DIR), "dataset")
DATA_OUT_DIR  = os.path.join(ML_DIR, "data")
REPORT_DIR    = os.path.join(ML_DIR, "reports")
os.makedirs(DATA_OUT_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

PHIUSIIL_PATH   = os.path.join(DATASET_DIR, "PhiUSIIL_Phishing_URL_Dataset.csv")
LEGITPHISH_PATH = os.path.join(DATASET_DIR, "url_features_extracted1.csv")
OUTPUT_CSV      = os.path.join(DATA_OUT_DIR, "dataset.csv")
PROVENANCE_MD   = os.path.join(DATA_OUT_DIR, "PROVENANCE.md")

MAX_PER_CLASS = 30_000
RANDOM_SEED   = 42
report_lines  = []

COMMON_BENIGN_PATHS = [
    "", "/", "/about", "/about-us", "/contact", "/privacy", "/terms", "/help",
    "/faq", "/docs", "/blog", "/news", "/products", "/services", "/category/news",
    "/wiki/Main_Page", "/wiki/Computer_science", "/questions/tagged/python",
    "/articles/2024/01/overview", "/user/profile", "/search?q=query",
    "/index.html", "/home", "/explore", "/pricing"
]

def rpt(msg):
    log.info(msg)
    report_lines.append(msg)

def load_phiusiil():
    rpt("=" * 60)
    rpt("DATASET 1: PhiUSIIL Phishing URL Dataset")
    rpt("=" * 60)
    rpt(f"File: {PHIUSIIL_PATH}")
    rpt(f"Size: {os.path.getsize(PHIUSIIL_PATH)/1e6:.1f} MB")
    df = pd.read_csv(PHIUSIIL_PATH, usecols=["URL", "label"], low_memory=False)
    rpt(f"Total rows: {len(df):,}")
    rpt(f"Original label dist: {df['label'].value_counts().to_dict()}")
    rpt("  label=1 -> Legitimate | label=0 -> Phishing (UCI / ScienceDirect definition)")
    # Normalize: 0 (phishing) -> 1, 1 (legitimate) -> 0
    df["label_unified"] = (df["label"] == 0).astype(int)
    df["source"] = "PhiUSIIL"
    df = df[df["URL"].notna() & (df["URL"].str.strip() != "") & df["label"].notna()]
    df = df.drop_duplicates(subset=["URL"], keep="first")
    rpt(f"Rows after dedup: {len(df):,}")
    rpt(f"Unified dist (1=Phish, 0=Legit): {df['label_unified'].value_counts().to_dict()}")
    return df[["URL", "label_unified", "source"]]

def load_legitphish():
    rpt("=" * 60)
    rpt("DATASET 2: LegitPhish URL Features Dataset")
    rpt("=" * 60)
    rpt(f"File: {LEGITPHISH_PATH}")
    rpt(f"Size: {os.path.getsize(LEGITPHISH_PATH)/1e6:.1f} MB")
    df = pd.read_csv(LEGITPHISH_PATH, usecols=["URL", "ClassLabel"], low_memory=False)
    rpt(f"Total rows: {len(df):,}")
    rpt(f"Original ClassLabel dist: {df['ClassLabel'].value_counts().to_dict()}")
    rpt("  ClassLabel=1 -> Legitimate | ClassLabel=0 -> Phishing (Mendeley definition)")
    # Normalize: 0 (phishing) -> 1, 1 (legitimate) -> 0
    df["label_unified"] = (df["ClassLabel"] == 0).astype(int)
    df["source"] = "LegitPhish"
    df = df[df["URL"].notna() & (df["URL"].str.strip() != "") & df["ClassLabel"].notna()]
    df = df.drop_duplicates(subset=["URL"], keep="first")
    rpt(f"Rows after dedup: {len(df):,}")
    rpt(f"Unified dist (1=Phish, 0=Legit): {df['label_unified'].value_counts().to_dict()}")
    return df[["URL", "label_unified", "source"]]

def debias_legitimate_url(url, rng):
    """Normalize domain formatting and add realistic benign web paths."""
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or parsed.path
        path = parsed.path
        query = parsed.query
        
        # 35% strip www. prefix
        if netloc.startswith("www.") and rng.random() < 0.35:
            netloc = netloc[4:]
            
        # 5% use http for legacy web support
        if rng.random() < 0.05:
            scheme = "http"
            
        # If no path present, augment 40% with realistic benign path
        if path in ("", "/"):
            if rng.random() < 0.40:
                path = rng.choice(COMMON_BENIGN_PATHS)
            else:
                path = ""
                
        rebuilt = f"{scheme}://{netloc}{path}"
        if query:
            rebuilt += f"?{query}"
        return rebuilt
    except Exception:
        return url

def main():
    start = datetime.now(timezone.utc)
    rng = random.Random(RANDOM_SEED)
    rpt(f"Started: {start.isoformat()}")
    rpt(f"Random seed: {RANDOM_SEED}, Max per class: {MAX_PER_CLASS:,}")

    df_p = load_phiusiil()
    rpt("")
    df_l = load_legitphish()
    rpt("")

    rpt("=" * 60)
    rpt("COMBINING DATASETS & RESOLVING OVERLAPS")
    rpt("=" * 60)
    df_combined = pd.concat([df_p, df_l], ignore_index=True)
    rpt(f"Combined before cross-dedup: {len(df_combined):,}")
    
    cross_dup = df_combined["URL"].duplicated(keep="first").sum()
    rpt(f"Cross-dataset duplicate URLs removed: {cross_dup}")
    df_combined = df_combined.drop_duplicates(subset=["URL"], keep="first")

    # Conflict detection
    url_label_counts = df_combined.groupby("URL")["label_unified"].nunique()
    conflicting = url_label_counts[url_label_counts > 1].index.tolist()
    rpt(f"Conflicting labels (same URL, different label): {len(conflicting)} -> removed")
    df_combined = df_combined[~df_combined["URL"].isin(conflicting)]
    rpt(f"After conflict removal: {len(df_combined):,}")
    rpt(f"Distribution: {df_combined['label_unified'].value_counts().to_dict()}")

    rpt("")
    rpt(f"Stratified sampling: {MAX_PER_CLASS:,} per class...")
    phish_df = df_combined[df_combined["label_unified"] == 1].sample(n=MAX_PER_CLASS, random_state=RANDOM_SEED)
    legit_df = df_combined[df_combined["label_unified"] == 0].sample(n=MAX_PER_CLASS, random_state=RANDOM_SEED)

    rpt(f"Applying benign URL distribution debiasing to {len(legit_df):,} legitimate URLs...")
    debiased_legit_urls = [debias_legitimate_url(u, rng) for u in legit_df["URL"]]
    legit_df = legit_df.copy()
    legit_df["URL"] = debiased_legit_urls

    df_final = pd.concat([legit_df, phish_df], ignore_index=True).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    rpt(f"Balanced Corpus: {len(df_final):,} rows ({df_final['label_unified'].value_counts().to_dict()})")

    rpt("")
    rpt(f"Extracting {len(FEATURE_NAMES)} URL-only features...")
    vectors = []
    failed = 0
    for i, url in enumerate(df_final["URL"]):
        try:
            feats, _ = extract_url_features(url)
            vec = features_to_vector(feats)
        except Exception:
            vec = None
            failed += 1
        vectors.append(vec)
        if (i + 1) % 15000 == 0:
            log.info(f"  {i+1:,}/{len(df_final):,} extracted...")

    rpt(f"Feature extraction done. Failed: {failed}")
    valid_mask = [v is not None for v in vectors]
    df_final_clean = df_final[valid_mask].reset_index(drop=True)
    valid_vecs = [v for v in vectors if v is not None]
    feat_df = pd.DataFrame(valid_vecs, columns=FEATURE_NAMES)
    df_out = pd.concat([df_final_clean, feat_df], axis=1)

    final_dist = df_out["label_unified"].value_counts().to_dict()
    rpt(f"Final exportable: {len(df_out):,} rows | {final_dist}")
    df_out.to_csv(OUTPUT_CSV, index=False)
    rpt(f"Saved to: {OUTPUT_CSV}")

    end = datetime.now(timezone.utc)
    elapsed = (end - start).total_seconds()

    prov_lines = [
        "# PhishGuard AI - Unified Dataset Provenance",
        f"Generated: {end.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Random Seed: {RANDOM_SEED}",
        "",
        "## Source 1: PhiUSIIL Phishing URL Dataset",
        f"- File: dataset/PhiUSIIL_Phishing_URL_Dataset.csv",
        f"- Original rows: {len(df_p):,}",
        "- Original encoding: label 0=Phishing, 1=Legitimate",
        "- Normalized: 1=Phishing, 0=Legitimate",
        "",
        "## Source 2: LegitPhish URL Features Dataset",
        f"- File: dataset/url_features_extracted1.csv",
        f"- Original rows: {len(df_l):,}",
        "- Original encoding: ClassLabel 0=Phishing, 1=Legitimate",
        "- Normalized: 1=Phishing, 0=Legitimate",
        "",
        "## Integration & Debiasing Policy",
        "- Only URL column and target label consumed from both datasets",
        "- All features re-extracted from scratch using PhishGuard AI lexical engine",
        "- Deduplication across datasets with conflict rejection",
        "- Benign URL debiasing: corrected Alexa crawl artifact where legitimate sites lacked paths and apex domain variations",
        f"- Balanced Stratified Corpus: {MAX_PER_CLASS:,} phishing + {MAX_PER_CLASS:,} legitimate",
        "",
        "## Final Dataset",
        f"- Total records: {len(df_out):,}",
        f"- Phishing (label=1): {final_dist.get(1,0):,}",
        f"- Legitimate (label=0): {final_dist.get(0,0):,}",
        f"- Feature count: {len(FEATURE_NAMES)} URL-only features",
        "- Class Mapping: 0=Legitimate, 1=Phishing",
    ]
    with open(PROVENANCE_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(prov_lines))

    report_path = os.path.join(REPORT_DIR, "dataset_preparation_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# Dataset Preparation Report\n\n```\n")
        f.write("\n".join(report_lines))
        f.write("\n```\n")

    rpt(f"DONE in {elapsed:.1f}s")

if __name__ == "__main__":
    main()
