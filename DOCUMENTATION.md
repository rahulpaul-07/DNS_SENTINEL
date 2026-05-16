# DNSentinel Precise ML Engine

DNSentinel now utilizes a hybrid, high-precision detection engine for DGA and DNS Tunneling.

## 🚀 Precise Training Engine
The `train_dga.py` script has been upgraded to a production-grade training pipeline:
- **Optimization**: AdamW with weight decay (L2 regularization) to prevent overfitting on benign traffic.
- **Scheduling**: `ReduceLROnPlateau` learning rate scheduling for surgical convergence.
- **Robustness**: Gradient clipping at $1.0$ norm to stabilize training on long domain sequences.
- **Evaluation**: Real-time tracking of F1-Score, Precision, Recall, and AUC-ROC.

## 🛠️ How to Retrain
To retrain the model on your custom logs:
1. Ensure your data is in `dga_dataset.csv`.
2. Run `python train_dga.py`.
3. The engine will automatically generate a best-in-class `dga_model_precise.pt` and update the active detector.

## 🤖 AI Logic (Extension)
The extension uses a **Hybrid Inference Mode**:
1. **Llama 3 (Groq)**: Provides high-level semantic reasoning and explainability.
2. **PIE Engine (Math)**: Provides low-latency structural risk assessment (Entropy, Digits).
3. **Local LSTM**: Provides sequence-based deep analysis for known exfiltration patterns.