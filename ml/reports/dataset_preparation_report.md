# Dataset Preparation Report

```
Started: 2026-10-26T05:38:12.703942+00:00
Random seed: 42, Max per class: 30,000
============================================================
DATASET 1: PhiUSIIL Phishing URL Dataset
============================================================
File: D:\git projects\phishing url detector\dataset\PhiUSIIL_Phishing_URL_Dataset.csv
Size: 56.9 MB
Total rows: 235,795
Original label dist: {1: 134850, 0: 100945}
  label=1 -> Legitimate | label=0 -> Phishing (UCI / ScienceDirect definition)
Rows after dedup: 235,370
Unified dist (1=Phish, 0=Legit): {0: 134850, 1: 100520}

============================================================
DATASET 2: LegitPhish URL Features Dataset
============================================================
File: D:\git projects\phishing url detector\dataset\url_features_extracted1.csv
Size: 9.0 MB
Total rows: 101,219
Original ClassLabel dist: {0.0: 63678, 1.0: 37540}
  ClassLabel=1 -> Legitimate | ClassLabel=0 -> Phishing (Mendeley definition)
Rows after dedup: 100,872
Unified dist (1=Phish, 0=Legit): {1: 63492, 0: 37380}

============================================================
COMBINING DATASETS & RESOLVING OVERLAPS
============================================================
Combined before cross-dedup: 336,242
Cross-dataset duplicate URLs removed: 36935
Conflicting labels (same URL, different label): 0 -> removed
After conflict removal: 299,307
Distribution: {1: 164012, 0: 135295}

Stratified sampling: 30,000 per class...
Applying benign URL distribution debiasing to 30,000 legitimate URLs...
Balanced Corpus: 60,000 rows ({0: 30000, 1: 30000})

Extracting 16 URL-only features...
Feature extraction done. Failed: 0
Final exportable: 60,000 rows | {0: 30000, 1: 30000}
Saved to: D:\git projects\phishing url detector\ml\data\dataset.csv
```
