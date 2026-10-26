# PhishGuard AI - Model Evaluation Report v3.0

Generated: 2026-10-26 12:52:07

## Dataset
- Total unique URLs used: 298,006
- Sources: PhiUSIIL + URLFeatures (all available data)
- Training set: 238,404
- Test set:     59,602

## 5-Fold Cross-Validation (on training set)
| Metric   | Mean    | Std     |
|----------|---------|---------|
| Accuracy | 0.9941 | 0.0002 |
| F1-Score | 0.9946  | 0.0001  |
| ROC-AUC  | 0.9981 | 0.0002 |

## Holdout Test Metrics
| Metric    | Value              |
|-----------|--------------------|
| Accuracy  | 0.993977 (99.40%) |
| Precision | 0.997342 (99.73%) |
| Recall    | 0.991611 (99.16%) |
| F1-Score  | 0.994468 (99.45%) |
| ROC-AUC   | 0.998051 (99.81%) |

## Confusion Matrix
|              | Pred Legit | Pred Phish |
|--------------|------------|------------|
| Actual Legit | TN=26,973  | FP=86  |
| Actual Phish | FN=273  | TP=32,270  |

## Feature Importances (Top 16)
| Feature | Importance |
|---------|-----------|
| is_https | 0.3895 |
| count_digits | 0.1641 |
| digit_ratio | 0.1345 |
| path_length | 0.1062 |
| count_slash | 0.0559 |
| count_subdomains | 0.0354 |
| url_length | 0.0345 |
| count_dots | 0.0268 |
| hostname_length | 0.0201 |
| special_char_ratio | 0.0176 |
| count_hyphens | 0.0086 |
| has_ip | 0.0053 |
| has_suspicious_keywords | 0.0010 |
| count_equal | 0.0003 |
| count_question | 0.0001 |
| count_at | 0.0001 |
