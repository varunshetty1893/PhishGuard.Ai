# ml/data/ — Dataset Provenance

`ml/data/dataset.csv` is **tracked in this repository via Git LFS** (see `.gitattributes`).
It is a 15 MB binary that Git LFS stores as a pointer stub in the tree and
downloads from LFS storage on `git lfs pull` or `git clone --recurse-submodules`.

If you cloned without LFS support and `dataset.csv` is only 133 bytes, run:

```bash
git lfs pull
```

## Dataset Composition

The processed dataset (`dataset.csv`) was produced by `ml/train_fulldata.py`
from two raw source files (not committed — too large for Git / LFS budget):

| Source file | Records | Phishing | Legitimate | Licence |
|---|---|---|---|---|
| `PhiUSIIL_Phishing_URL_Dataset.csv` | 235,795 | 100,945 | 134,850 | CC BY 4.0 |
| `url_features_extracted1.csv` | 101,219 | 37,540 | 63,678 | Research dataset |
| **Combined (after dedup + split)** | **~40,000 sampled** | — | — | — |

The final dataset contains 40,000 rows (train/val/test split 60/22.5/17.5 %)
with 16 lexical/structural features extracted per URL.

## How to reproduce from scratch

```bash
# 1. Place raw source CSVs in ml/dataset/ (not tracked)
# 2. Extract features and produce dataset.csv:
python ml/train_fulldata.py

# 3. Train the 3-way split model and regenerate all artifacts:
python ml/train_three_split_model.py

# 4. Or run the combined reproduce script:
python scripts/reproduce_all.py
```

`scripts/reproduce_all.py` runs both steps and validates that the output
`ml/artifacts/phishguard_rf_model.joblib` is a real binary (not an LFS pointer)
before mirroring it to `backend/app/ml/artifacts/`.

## Feature Schema (16 features, model v4.1.0)

The 16-feature schema is documented in `ml/ML_METHODOLOGY.md`.
Any change to the feature list requires retraining and a new model version.

## Raw Data Sources

- **PhiUSIIL**: <https://archive.ics.uci.edu/dataset/967>  
  Hannousse, A., & Yahiouche, S. (2023). CC BY 4.0.
- **url_features_extracted1**: proprietary research dataset — contact repo owner for access.
