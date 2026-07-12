# Model Card — DNSentinel DNS Threat Classifier

A concise, honest description of the model behind DNSentinel's `/analyze`
endpoint. Every metric here is produced by `backend/evaluate.py` (no
hand-typed numbers) and can be reproduced in under a minute.

## Overview

| | |
|---|---|
| **Task** | Binary classification of DNS queries: benign (0) vs. malicious (1), targeting DGA domains and DNS-based data exfiltration. |
| **Model** | `RandomForestClassifier` (300 trees, `max_depth=30`, `min_samples_split=10`, `random_state=42`) as the primary classifier, ensembled with an `IsolationForest` anomaly detector and an **optional** character-level deep-learning DGA scorer (`backend/dga_model.py`, skipped when `torch` is absent). |
| **Input** | A single DNS query string → a **22-dimensional feature vector** (`backend/features.py`). |
| **Output** | `(label, malicious_probability ∈ [0,1], anomaly_flag, SHAP explanation)`. Decision threshold = 0.5. |
| **Intended use** | Portfolio / research demonstrator for DNS threat detection and SOC workflow tooling. **Not** production-hardened for enterprise deployment as-is. |

## Features (22)

Shannon entropy, query length, subdomain length, English-bigram likelihood,
consonant/digit/unique-character ratios, vowel:consonant ratio, four
max-continuous-run features (numeric, alphabetic, consonant, same-char), upper/
lower/special counts, label count/max/average, entropy-to-length ratio, a
high-entropy flag, and a derived domain-complexity term. Full definitions in
`backend/features.py`; ordering is contract-tested in
`backend/tests/test_model_contract.py`.

## Training data

| Dataset | Rows | Balance | Notes |
|---|---|---|---|
| `data/dns_exfiltration_dataset.csv` | 700 | 350/350 | Exfil-style vs. benign domains. |
| `backend/dga_dataset.csv` | 1,000 | 500/500 | Algorithmically-generated vs. benign domains. |

**Limitation — separability.** These bundled sets are small and near-linearly
separable: an **entropy-only, depth-1 decision stump reaches F1 ≈ 0.99** on the
exfil set. Near-100% in-distribution scores therefore reflect *dataset
simplicity*, not model superiority, and should not be read as production
accuracy.

## Evaluation

Reproduce:

```bash
pip install -r backend/requirements.txt
python -m backend.evaluate --dataset data/dns_exfiltration_dataset.csv --cross backend/dga_dataset.csv
python -m backend.evaluate --dataset backend/dga_dataset.csv         --cross data/dns_exfiltration_dataset.csv
```

**In-distribution (stratified 80/20 hold-out and 5-fold CV):**

| Dataset | Split | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|---|
| exfil (700) | hold-out | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| exfil (700) | 5-fold CV | 1.000 | 1.000 | 1.000 | 1.000 | — |
| dga (1,000) | hold-out | 0.995 | 0.990 | 1.000 | 0.995 | 1.000 |
| dga (1,000) | 5-fold CV | 0.997 | 0.994 | 1.000 | 0.997 | — |

**Cross-dataset generalization (train on one, test on the other — the honest signal):**

| Train → Test | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| exfil → dga | 0.593 | 0.551 | 1.000 | 0.711 | 0.988 |
| dga → exfil | 0.924 | 1.000 | 0.849 | 0.918 | 1.000 |

Under distribution shift, precision falls as low as **0.55** (407 false
positives in the exfil→dga direction). In a SOC, that false-positive rate — not
in-distribution accuracy — is the metric that governs analyst alert fatigue.

## Known limitations & ethical considerations

- **Domain shift** is the dominant failure mode (see above). Deploying on live
  traffic requires retraining on representative, diverse data.
- **Synthetic/curated data** inflates in-distribution scores; treat them as a
  functional smoke test, not a capability claim.
- **No adversarial robustness** evaluation. Dictionary-based DGAs (e.g.
  suppobox, matsnu) that mimic natural language are expected to be much harder
  than the random-looking DGAs in the bundled set.
- **Threshold (0.5) is uncalibrated.** A precision-recall-curve-driven
  operating point is future work.

## Roadmap to production-grade rigor

Benchmark against public corpora (CIC-Bell-DNS-EXF-2021 for exfil; Bambenek/
UMUDGA/DGArchive vs. Tranco for DGA), report per-DGA-family recall, calibrate
the decision threshold to a target false-positive budget, and track metric
drift in CI.
