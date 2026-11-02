#!/usr/bin/env python3
"""
scripts/reproduce_all.py
========================
Full reproduction script: dataset preparation → model training → artifact validation.

Usage:
    python scripts/reproduce_all.py [--skip-train]

Steps:
    1. Verify raw source CSVs are present in ml/dataset/
    2. Run ml/train_fulldata.py  →  produces ml/data/dataset.csv
    3. Run ml/train_three_split_model.py  →  produces artifacts in ml/artifacts/
    4. Mirror artifacts to backend/app/ml/artifacts/
    5. Validate that output is a real binary (NOT a Git LFS pointer)
    6. Print a summary with key metrics from model_metadata.json

Requires:
    pip install pandas scikit-learn joblib numpy

WARNING: Full training takes ~10–30 minutes on a modern laptop.
         Use --skip-train to only validate existing artifacts.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ML_DIR = REPO_ROOT / "ml"
ARTIFACTS_DIR = ML_DIR / "artifacts"
BACKEND_ARTIFACTS = REPO_ROOT / "backend" / "app" / "ml" / "artifacts"
DATASET_CSV = ML_DIR / "data" / "dataset.csv"
MODEL_JOBLIB = ARTIFACTS_DIR / "phishguard_rf_model.joblib"
METADATA_JSON = ARTIFACTS_DIR / "model_metadata.json"

GIT_LFS_HEADER = b"version https://git-lfs"


def is_lfs_pointer(path: Path) -> bool:
    """Return True if the file is a Git LFS pointer stub (< 200 bytes, starts with LFS header)."""
    if not path.exists():
        return False
    if path.stat().st_size > 200:
        return False
    with open(path, "rb") as fh:
        return fh.read(30).startswith(GIT_LFS_HEADER)


def run(cmd: list, cwd: Path = REPO_ROOT) -> None:
    print(f"\n>>> {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd, cwd=cwd)
    if result.returncode != 0:
        print(f"[ERROR] Command failed with exit code {result.returncode}")
        sys.exit(result.returncode)


def check_raw_sources() -> None:
    dataset_dir = ML_DIR / "dataset"
    required = [
        "PhiUSIIL_Phishing_URL_Dataset.csv",
        "url_features_extracted1.csv",
    ]
    missing = [f for f in required if not (dataset_dir / f).exists()]
    if missing:
        print("[ERROR] Missing raw source files in ml/dataset/:")
        for f in missing:
            print(f"  - {f}")
        print(
            "\nDownload instructions are in ml/data/PROVENANCE.md.\n"
            "Place the files in ml/dataset/ before running this script."
        )
        sys.exit(1)
    print("[OK] Raw source CSVs found.")


def mirror_artifacts() -> None:
    BACKEND_ARTIFACTS.mkdir(parents=True, exist_ok=True)
    for src in ARTIFACTS_DIR.glob("*"):
        dst = BACKEND_ARTIFACTS / src.name
        shutil.copy2(src, dst)
        print(f"  Mirrored {src.name} -> {dst.relative_to(REPO_ROOT)}")


def validate_outputs() -> None:
    errors = []

    if not MODEL_JOBLIB.exists():
        errors.append(f"Model artifact not found: {MODEL_JOBLIB}")
    elif is_lfs_pointer(MODEL_JOBLIB):
        errors.append(
            "Model is a Git LFS pointer stub — training did not produce a real artifact.\n"
            "  Run `git lfs pull` or retrain from scratch."
        )
    else:
        size_mb = MODEL_JOBLIB.stat().st_size / 1_048_576
        print(f"[OK] Model artifact: {MODEL_JOBLIB.name} ({size_mb:.1f} MB)")

    if not DATASET_CSV.exists():
        errors.append(f"Dataset CSV not found: {DATASET_CSV}")
    elif is_lfs_pointer(DATASET_CSV):
        errors.append("dataset.csv is a Git LFS pointer — run `git lfs pull` or regenerate.")
    else:
        size_mb = DATASET_CSV.stat().st_size / 1_048_576
        print(f"[OK] Dataset CSV: {DATASET_CSV.name} ({size_mb:.1f} MB)")

    if not METADATA_JSON.exists():
        errors.append(f"model_metadata.json not found: {METADATA_JSON}")
    else:
        with open(METADATA_JSON) as fh:
            meta = json.load(fh)
        required_keys = [
            "model_version", "decision_threshold",
            "training_samples", "validation_samples", "test_samples",
            "test_accuracy", "test_f1",
        ]
        missing_keys = [k for k in required_keys if k not in meta]
        if missing_keys:
            errors.append(f"model_metadata.json missing keys: {missing_keys}")
        else:
            total = (
                meta["training_samples"]
                + meta["validation_samples"]
                + meta["test_samples"]
            )
            print(
                "\n[METRICS] model_metadata.json\n"
                f"  Version       : {meta['model_version']}\n"
                f"  Total samples : {total:,}\n"
                f"  Threshold     : {meta['decision_threshold']}\n"
                f"  Test accuracy : {meta['test_accuracy']:.4f}\n"
                f"  Test F1       : {meta['test_f1']:.4f}\n"
            )

    if errors:
        print("\n[FAIL] Validation errors:")
        for e in errors:
            print(f"  x {e}")
        sys.exit(1)

    print("[PASS] All artifacts validated successfully.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Reproduce PhishGuard AI ML pipeline.")
    parser.add_argument(
        "--skip-train",
        action="store_true",
        help="Skip training steps; only mirror and validate existing artifacts.",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("PhishGuard AI -- Full Reproduction Pipeline")
    print("=" * 60)

    if not args.skip_train:
        # Step 1: verify raw data
        check_raw_sources()

        # Step 2: produce dataset.csv
        run([sys.executable, str(ML_DIR / "train_fulldata.py")])

        # Step 3: train + evaluate model
        run([sys.executable, str(ML_DIR / "train_three_split_model.py")])
    else:
        print("[SKIPPED] Training steps (--skip-train). Validating existing artifacts.")

    # Step 4: mirror to backend
    print("\nMirroring artifacts to backend...")
    mirror_artifacts()

    # Step 5 + 6: validate
    print("\nValidating outputs...")
    validate_outputs()

    print("\n[OK] Reproduction complete.")


if __name__ == "__main__":
    main()
