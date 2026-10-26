# PhishGuard AI - Model Training & Evaluation Report

- **Date Executed:** 2026-10-26T04:29:54.126516+00:00
- **Model Version:** 1.0.0
- **Primary Algorithm:** Random Forest Classifier
- **Baseline Algorithm:** Logistic Regression

## 1. Dataset Partitioning
- **Total Ingested Samples:** 5,000
- **Training Samples (80%):** 4,000
- **Held-Out Test Samples (20%):** 1,000
- **Stratification:** Balanced 50% Phishing / 50% Legitimate

## 2. Performance Comparison

| Metric | Random Forest (Primary) | Logistic Regression (Baseline) | Delta |
|---|---|---|---|
| **Accuracy** | **100.00%** | 99.90% | +0.10% |
| **Precision** | **100.00%** | 100.00% | +0.00% |
| **Recall (Sensitivity)** | **100.00%** | 99.80% | +0.20% |
| **F1-Score** | **100.00%** | 99.90% | +0.10% |
| **ROC-AUC** | **1.0000** | 1.0000 | +0.0000 |

## 3. Confusion Matrix (Held-out Test Partition)
- **True Negatives (Legitimate correctly identified):** 500
- **False Positives (Legitimate falsely flagged):** 0
- **False Negatives (Phishing missed):** 0
- **True Positives (Phishing correctly caught):** 500

## 4. Top Feature Importances (MDI)
- **`count_digits`**: 33.17%
- **`is_https`**: 22.81%
- **`count_dots`**: 18.10%
- **`hostname_length`**: 12.22%
- **`is_ip_address`**: 5.40%
- **`path_length`**: 2.96%
- **`url_length`**: 2.09%
- **`count_subdomains`**: 1.30%
- **`count_special_chars`**: 0.94%
- **`query_length`**: 0.49%
- **`has_suspicious_keywords`**: 0.31%
- **`is_shortened_service`**: 0.10%
- **`count_hyphens`**: 0.08%
- **`has_suspicious_encoding`**: 0.00%
- **`has_at_symbol`**: 0.00%
- **`has_unusual_port`**: 0.00%
