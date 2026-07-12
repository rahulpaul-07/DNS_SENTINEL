# models/

Model artifacts are **generated, not committed** — they are reproducible outputs
of a seeded training run, so there is no reason to version binary blobs.

## Regenerate

```bash
pip install -r backend/requirements.txt
python -m backend.train                       # trains on the bundled exfil dataset
# or point at another labelled CSV:
python -m backend.train --dataset backend/dga_dataset.csv
```

This writes:

| File | What |
|---|---|
| `dns_rf_model.joblib` | RandomForest classifier (seed=42, deterministic) |
| `dns_iso_model.joblib` | IsolationForest anomaly detector (seed=42) |
| `metrics.json` | Provenance manifest: dataset SHA-256, library versions, hyperparameters, and held-out metrics |

`metrics.json` **is** committed as the reproducible record of how the shipped
numbers were produced. The `.joblib` files are git-ignored. On first request the
backend auto-trains them if the directory is empty (`model.load_models()`).

Honest evaluation (hold-out + 5-fold + cross-dataset generalization) lives in
[`../evaluate.py`](../evaluate.py); see [`../../MODEL_CARD.md`](../../MODEL_CARD.md).
