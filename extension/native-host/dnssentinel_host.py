#!/usr/bin/env python3
import sys
import json
import struct
import os
import joblib
import pandas as pd
import numpy as np
import time

# Pre-load models to ensure <50ms latency per request
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Models are generated reproducibly into backend/models/ by `python -m backend.train`.
MODEL_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", "backend", "models"))
RF_PATH = os.path.join(MODEL_DIR, "dns_rf_model.joblib")
ISO_PATH = os.path.join(MODEL_DIR, "dns_iso_model.joblib")

rf_model = None
iso_model = None
try:
    if os.path.exists(RF_PATH):
        rf_model = joblib.load(RF_PATH)
    if os.path.exists(ISO_PATH):
        iso_model = joblib.load(ISO_PATH)
except Exception:
    pass

def read_message():
    raw_length = sys.stdin.buffer.read(4)
    if len(raw_length) == 0:
        sys.exit(0)
    message_length = struct.unpack('@I', raw_length)[0]
    message = sys.stdin.buffer.read(message_length).decode('utf-8')
    return json.loads(message)

def send_message(message):
    encoded = json.dumps(message).encode('utf-8')
    sys.stdout.buffer.write(struct.pack('@I', len(encoded)))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()

def main():
    while True:
        try:
            msg = read_message()
            start_time = time.time()
            features = msg.get("features", [])
            
            if not rf_model or len(features) < 22:
                # Fallback response if models missing or invalid data
                send_message({
                    "ml_score": 0.5,
                    "isolation_score": 0.5,
                    "final_score": 50,
                    "shap_reason": "Native ML Models unavailable.",
                    "error": True,
                    "latency_ms": int((time.time() - start_time) * 1000)
                })
                continue

            # Ensure correct shape
            X = pd.DataFrame([features])
            
            # 1. Random Forest Score
            probabilities = rf_model.predict_proba(X)[0]
            ml_score = float(probabilities[1]) # Malicious class
            
            # 2. Isolation Forest Score
            iso_score = float(iso_model.predict(X)[0]) if iso_model else 1
            
            final_score = ml_score * 100
            shap_reason = ""
            
            if final_score > 60:
                shap_reason = "High probability of tunneling/exfiltration based on ML profile."

            send_message({
                "ml_score": ml_score,
                "isolation_score": iso_score,
                "final_score": final_score,
                "shap_reason": shap_reason,
                "latency_ms": int((time.time() - start_time) * 1000)
            })

        except Exception as e:
            send_message({"error": str(e)})

if __name__ == '__main__':
    main()
