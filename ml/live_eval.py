#!/usr/bin/env python3
"""
ml/live_eval.py -- PhishGuard AI Live Evaluation Script
========================================================
Fetches today's phishing URLs (OpenPhish + URLhaus) and a natural mix of
legitimate URLs (Tranco top-50k with realistic paths), then runs ML inference
ONLY (threat feeds disabled) to compute recall, FPR, and 95% Wilson CIs.

Writes: ml/reports/live_eval_YYYY-MM-DD.json

Usage:
    python ml/live_eval.py [--max-phish N] [--max-legit N]

Flags:
    --max-phish  Max phishing URLs to evaluate (default: 300)
    --max-legit  Max legitimate URLs to evaluate (default: 300)
    --dry-run    Print counts only, skip model inference
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import math
import random
import sys
import time
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urlparse

# -- Path bootstrap ----------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

import urllib.request as _req

# -- Constants ----------------------------------------------------------------
OPENPHISH_FEED   = "https://openphish.com/feed.txt"
URLHAUS_CSV      = "https://urlhaus.abuse.ch/downloads/csv_recent/"
TRANCO_LIST_PATH = ROOT / "ml" / "data" / "tranco_top50k.txt"
REPORT_DIR       = ROOT / "ml" / "reports"
MODEL_METADATA   = ROOT / "backend" / "app" / "ml" / "artifacts" / "model_metadata.json"
MODEL_PATH       = ROOT / "backend" / "app" / "ml" / "artifacts" / "phishguard_rf_model.joblib"

FETCH_TIMEOUT = 15  # seconds per HTTP request

# Realistic path templates used when building legit deep-link URLs
REALISTIC_PATH_TEMPLATES = [
    "/login", "/signin", "/account/login", "/user/login", "/auth/signin",
    "/dashboard", "/profile", "/settings", "/account/settings",
    "/product/{id}", "/shop/item/{id}", "/p/{id}", "/items/{id}",
    "/blog/{slug}", "/news/{slug}", "/articles/{slug}", "/post/{slug}",
    "/docs/getting-started", "/docs/api", "/help/faq", "/support",
    "/checkout", "/cart", "/order/{id}", "/orders",
    "/search?q=login", "/search?q=account", "/search?q=help",
    "/en/login", "/en/signin", "/en/account",
    "/app/dashboard", "/app/settings", "/app/profile",
    "/.well-known/openid-configuration",
    "/oauth/authorize?response_type=code&client_id=app",
    "/api/v1/health", "/api/v2/users",
    "/about", "/contact", "/pricing", "/plans",
    "/reset-password", "/forgot-password", "/verify-email",
    "/signup", "/register", "/create-account",
]

# -- Wilson 95% CI ------------------------------------------------------------
def ci_95(p: float, n: int) -> tuple[float, float]:
    if n == 0:
        return 0.0, 1.0
    se = math.sqrt(p * (1 - p) / n)
    return max(0.0, p - 1.96 * se), min(1.0, p + 1.96 * se)


# -- HTTP helpers --------------------------------------------------------------
def _fetch_text(url: str, timeout: int = FETCH_TIMEOUT) -> str | None:
    try:
        with _req.urlopen(url, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception as exc:
        print(f"  [WARN] Failed to fetch {url}: {exc}", file=sys.stderr)
        return None


# -- Phishing URL collectors ---------------------------------------------------
def collect_openphish(max_n: int) -> list[str]:
    """Fetch OpenPhish plaintext feed -> list of phishing URLs."""
    text = _fetch_text(OPENPHISH_FEED)
    if not text:
        return []
    urls = [line.strip() for line in text.splitlines() if line.strip().startswith("http")]
    random.shuffle(urls)
    return urls[:max_n]


def collect_urlhaus(max_n: int) -> list[str]:
    """Fetch URLhaus recent CSV -> list of active phishing/malware URLs."""
    text = _fetch_text(URLHAUS_CSV)
    if not text:
        return []
    urls: list[str] = []
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        # URLhaus CSV columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
        if len(row) < 3:
            continue
        url = row[2].strip()
        status = row[3].strip().lower() if len(row) > 3 else ""
        # Prefer "online" entries for the live eval; accept "unknown" too
        if url.startswith("http") and status in ("online", "unknown", ""):
            urls.append(url)
    random.shuffle(urls)
    return urls[:max_n]


# -- Legit URL builder ---------------------------------------------------------
def collect_legit_urls(max_n: int) -> list[str]:
    """
    Sample domains from the local Tranco list and attach realistic paths.
    Falls back to a small hardcoded set if the file is missing.
    """
    domains: list[str] = []
    if TRANCO_LIST_PATH.exists():
        with open(TRANCO_LIST_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # Tranco file may be "rank,domain" or just "domain"
                parts = line.split(",")
                domain = parts[-1].strip().lower()
                if domain and "." in domain:
                    domains.append(domain)
        print(f"  Tranco domains loaded: {len(domains):,}")
    else:
        print("  [WARN] Tranco list not found; using hardcoded fallback domains", file=sys.stderr)
        domains = [
            "google.com", "github.com", "microsoft.com", "apple.com",
            "amazon.com", "wikipedia.org", "stackoverflow.com", "python.org",
            "mozilla.org", "linkedin.com", "twitter.com", "facebook.com",
            "netflix.com", "adobe.com", "dropbox.com", "slack.com",
            "zoom.us", "notion.so", "stripe.com", "shopify.com",
        ]

    # Pick random domains and attach random paths
    random.shuffle(domains)
    selected = domains[:max_n]
    templates = REALISTIC_PATH_TEMPLATES[:]
    legit_urls: list[str] = []
    for i, domain in enumerate(selected):
        tmpl = templates[i % len(templates)]
        # Fill {id} / {slug} placeholders
        path = tmpl.replace("{id}", str(random.randint(100, 9999)))
        path = path.replace("{slug}", f"article-{random.randint(1, 999)}")
        legit_urls.append(f"https://{domain}{path}")
    return legit_urls


# -- ML inference (no threat feeds) -------------------------------------------
def load_model_direct():
    """
    Load model + metadata directly via joblib (bypasses all threat feeds,
    RDAP, DNS -- pure ML pipeline only).
    """
    import joblib
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model not found: {MODEL_PATH}")
    artifact = joblib.load(str(MODEL_PATH))
    # The joblib may be a dict wrapping the model, or the model directly
    if isinstance(artifact, dict):
        model = artifact.get("model") or artifact.get("base_model")
        threshold = float(
            artifact.get("decision_threshold") or
            artifact.get("optimal_threshold") or
            0.5
        )
        metadata = artifact
    else:
        model = artifact
        metadata = {}
        if MODEL_METADATA.exists():
            with open(MODEL_METADATA, encoding="utf-8") as fmeta:
                metadata = json.load(fmeta)
        threshold = float(
            metadata.get("decision_threshold") or
            metadata.get("optimal_threshold") or
            0.5
        )
    return model, threshold, metadata


def predict_ml_only(model, threshold: float, urls: list[str]) -> list[dict]:
    """
    Run feature extraction + model.predict_proba for each URL.
    Returns list of {"url": str, "prob": float, "predicted": int}
    """
    from backend.app.ml.feature_extraction_v2 import (  # type: ignore[import]
        FEATURE_NAMES, normalize_url,
    )

    results: list[dict] = []
    feature_matrix: list[list] = []
    valid_urls: list[str] = []

    # Import extract_features_v5 once, outside the loop
    try:
        from ml.train_v5_candidate import extract_features_v5  # type: ignore[import]
    except ImportError:
        from train_v5_candidate import extract_features_v5  # type: ignore[import]

    # Build feature matrix
    for url in urls:
        try:
            feats = extract_features_v5(url)
            # extract_features_v5 returns a list already in FEATURE_NAMES order
            if isinstance(feats, dict):
                row = [feats.get(name, 0) for name in FEATURE_NAMES]
            else:
                row = list(feats)
            feature_matrix.append(row)
            valid_urls.append(url)
        except Exception:
            # Skip URLs that error in feature extraction
            results.append({"url": url, "prob": None, "predicted": -1, "error": True})

    if not feature_matrix:
        return results

    import numpy as np
    X = np.array(feature_matrix, dtype=float)
    probs = model.predict_proba(X)[:, 1]

    for url, prob in zip(valid_urls, probs):
        results.append({
            "url": url,
            "prob": float(prob),
            "predicted": 1 if prob >= threshold else 0,
            "error": False,
        })
    return results


# -- Main ----------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="PhishGuard AI Live Evaluation")
    parser.add_argument("--max-phish", type=int, default=300,
                        help="Max phishing URLs to sample (default: 300)")
    parser.add_argument("--max-legit", type=int, default=300,
                        help="Max legitimate URLs to sample (default: 300)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Collect URLs and print counts; skip inference")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for reproducibility")
    args = parser.parse_args()

    random.seed(args.seed)
    today = date.today().isoformat()
    run_ts = datetime.now(tz=__import__("datetime").timezone.utc).isoformat()

    print("=" * 70)
    print("  PhishGuard AI -- Live Evaluation")
    print(f"  Date: {today}  |  Seed: {args.seed}")
    print("=" * 70)

    # -- 1. Collect phishing URLs ------------------------------------------
    print("\n[1/4] Fetching phishing URLs ...")
    half = args.max_phish // 2

    print(f"  OpenPhish (target: {half}) ...")
    t0 = time.time()
    op_urls = collect_openphish(half)
    print(f"  -> {len(op_urls)} URLs  ({time.time()-t0:.1f}s)")

    print(f"  URLhaus   (target: {half}) ...")
    t0 = time.time()
    uh_urls = collect_urlhaus(half)
    print(f"  -> {len(uh_urls)} URLs  ({time.time()-t0:.1f}s)")

    phish_urls = op_urls + uh_urls
    random.shuffle(phish_urls)
    # Deduplicate
    seen: set[str] = set()
    phish_urls_dedup: list[str] = []
    for u in phish_urls:
        if u not in seen:
            seen.add(u)
            phish_urls_dedup.append(u)
    phish_urls = phish_urls_dedup[:args.max_phish]
    print(f"  Total phishing (deduped): {len(phish_urls)}")

    # -- 2. Collect legitimate URLs ----------------------------------------
    print(f"\n[2/4] Building legitimate deep-link URLs (target: {args.max_legit}) ...")
    legit_urls = collect_legit_urls(args.max_legit)
    print(f"  Total legitimate: {len(legit_urls)}")

    if args.dry_run:
        print("\n[DRY RUN] Skipping inference.")
        print(f"  Would evaluate {len(phish_urls)} phishing + {len(legit_urls)} legit = "
              f"{len(phish_urls)+len(legit_urls)} total URLs")
        return

    if len(phish_urls) == 0:
        print("\n[ERROR] Zero phishing URLs collected -- cannot compute recall. "
              "Check network access to OpenPhish / URLhaus.", file=sys.stderr)
        sys.exit(1)
    if len(legit_urls) == 0:
        print("\n[ERROR] Zero legitimate URLs built. Check Tranco list path.", file=sys.stderr)
        sys.exit(1)

    # -- 3. Load model -----------------------------------------------------
    print("\n[3/4] Loading ML model (direct, no threat feeds) ...")
    t0 = time.time()
    model, threshold, metadata = load_model_direct()
    print(f"  Model loaded in {time.time()-t0:.1f}s  |  threshold={threshold:.4f}")

    # -- 4. Run inference --------------------------------------------------
    print(f"\n[4/4] Running inference on {len(phish_urls)} phishing + {len(legit_urls)} legit ...")

    t0 = time.time()
    phish_results = predict_ml_only(model, threshold, phish_urls)
    legit_results = predict_ml_only(model, threshold, legit_urls)
    elapsed = time.time() - t0
    print(f"  Inference complete in {elapsed:.1f}s")

    # -- Metrics -----------------------------------------------------------
    # Phishing: true positive = predicted 1
    ph_valid = [r for r in phish_results if not r.get("error")]
    le_valid = [r for r in legit_results if not r.get("error")]

    n_phish = len(ph_valid)
    n_legit = len(le_valid)
    tp = sum(1 for r in ph_valid if r["predicted"] == 1)
    fp = sum(1 for r in le_valid if r["predicted"] == 1)

    recall = tp / n_phish if n_phish > 0 else 0.0
    fpr    = fp / n_legit if n_legit > 0 else 0.0
    recall_ci = ci_95(recall, n_phish)
    fpr_ci    = ci_95(fpr, n_legit)

    print(f"\n{'-'*50}")
    print(f"  Phishing URLs evaluated : {n_phish:4d}  (errors: {len(phish_results)-n_phish})")
    print(f"  Legit URLs evaluated    : {n_legit:4d}  (errors: {len(legit_results)-n_legit})")
    print(f"  Recall (phish detected) : {recall*100:.1f}%  "
          f"95% CI [{recall_ci[0]*100:.1f}%-{recall_ci[1]*100:.1f}%]")
    print(f"  FPR (legit flagged)     : {fpr*100:.1f}%  "
          f"95% CI [{fpr_ci[0]*100:.1f}%-{fpr_ci[1]*100:.1f}%]")
    print(f"{'-'*50}")

    # -- Write report ------------------------------------------------------
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORT_DIR / f"live_eval_{today}.json"

    report: dict = {
        "generated_at": run_ts,
        "eval_date": today,
        "seed": args.seed,
        "model": {
            "threshold": threshold,
            "model_version": metadata.get("model_version", "unknown"),
            "trained_at": metadata.get("trained_at", "unknown"),
            "n_features": metadata.get("n_features", len(metadata.get("feature_names", []))),
        },
        "data_sources": {
            "phishing": {
                "openphish_count": len(op_urls),
                "urlhaus_count": len(uh_urls),
                "total_after_dedup": len(phish_urls),
                "evaluated": n_phish,
                "errors": len(phish_results) - n_phish,
            },
            "legitimate": {
                "source": "Tranco top-50k with realistic paths",
                "total_built": len(legit_urls),
                "evaluated": n_legit,
                "errors": len(legit_results) - n_legit,
            },
        },
        "metrics": {
            "recall": round(recall, 6),
            "recall_ci_95_low":  round(recall_ci[0], 6),
            "recall_ci_95_high": round(recall_ci[1], 6),
            "true_positives": tp,
            "false_negatives": n_phish - tp,
            "fpr": round(fpr, 6),
            "fpr_ci_95_low":  round(fpr_ci[0], 6),
            "fpr_ci_95_high": round(fpr_ci[1], 6),
            "false_positives": fp,
            "true_negatives": n_legit - fp,
        },
        "inference_time_seconds": round(elapsed, 2),
    }

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\n  Report written to: {report_path.relative_to(ROOT)}")
    print("=" * 70)


if __name__ == "__main__":
    main()

