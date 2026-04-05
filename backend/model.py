import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import numpy as np
import joblib
import os
import csv
from features import extract_features
from explainability import get_shap_explanation

# Paths to serialized models
RF_MODEL_PATH = os.path.join(os.path.dirname(__file__), "dns_rf_model_v5.joblib")
ISO_MODEL_PATH = os.path.join(os.path.dirname(__file__), "dns_iso_model_v5.joblib")

def train_base_model():
    # Load real Kaggle dataset to turbocharge the baseline model
    dataset_path = os.path.join(os.path.dirname(__file__), "..", "data", "dns_exfiltration_dataset.csv")
    print(f"[*] Bootstrapping powerful baseline model from {dataset_path}...")
    
    dataset = []
    with open(dataset_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            q = row.get('domain', '')
            if not q: continue
            
            log = {'query': q, 'source_ip': '0.0.0.0'}
            feats = extract_features(log)
            
            dataset.append({
                'entropy': feats['entropy'],
                'length': feats['length'],
                'subdomain_length': feats['subdomain_length'],
                'ngram_score': feats['ngram_score'],
                'frequency': 1, # Default normalized
                'consonant_ratio': feats['consonant_ratio'],
                'digit_ratio': feats['digit_ratio'],
                'unique_char': feats['unique_char'],
                'vowels_consonant_ratio': feats['vowels_consonant_ratio'],
                'max_continuous_numeric_len': feats['max_continuous_numeric_len'],
                'max_continuous_alphabet_len': feats['max_continuous_alphabet_len'],
                'max_continuous_consonants_len': feats['max_continuous_consonants_len'],
                'max_continuous_same_char': feats['max_continuous_same_char'],
                'upper_count': feats['upper_count'],
                'lower_count': feats['lower_count'],
                'special_count': feats['special_count'],
                'labels': feats['labels'],
                'labels_max': feats['labels_max'],
                'labels_average': feats['labels_average'],
                'entropy_to_length_ratio': feats['entropy_to_length_ratio'],
                'high_entropy_flag': feats['high_entropy_flag'],
                'domain_complexity': feats['domain_complexity'],
                'label': int(row.get('label', 0))
            })
            
    df = pd.DataFrame(dataset)
    X = df.drop(columns=['label'])
    y = df['label']
    
    # 1. High-Performance Random Forest (Supervised)
    print("[*] Training Kaggle-parity Random Forest Classifier...")
    rf_clf = RandomForestClassifier(n_estimators=300, max_depth=30, min_samples_split=10, random_state=42)
    rf_clf.fit(X, y)
    joblib.dump(rf_clf, RF_MODEL_PATH)
    
    # 2. Isolation Forest (Unsupervised Anomaly Detection)
    print("[*] Training Kaggle-parity Isolation Forest Anomaly Detector...")
    iso_clf = IsolationForest(contamination=0.15, random_state=42)
    iso_clf.fit(X)
    joblib.dump(iso_clf, ISO_MODEL_PATH)
    
    return rf_clf, iso_clf

def train_custom_model(df):
    """
    Trains the ML Ensemble on a REAL uploaded dataset.
    Expects df to have feature columns + 'label' (1 for Malicious, 0 for Benign).
    """
    if 'label' not in df.columns:
        raise ValueError("Dataset must contain a 'label' column for supervised training.")
        
    X = df.drop(columns=['label'])
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    rf_clf = RandomForestClassifier(n_estimators=150, max_depth=10, random_state=42)
    rf_clf.fit(X_train, y_train)
    joblib.dump(rf_clf, RF_MODEL_PATH)
    
    y_pred = rf_clf.predict(X_test)
    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_test, y_pred, zero_division=0)),
        "feature_importances": dict(zip(X.columns, map(float, rf_clf.feature_importances_)))
    }
    
    iso_clf = IsolationForest(contamination=0.15, random_state=42)
    iso_clf.fit(X)
    joblib.dump(iso_clf, ISO_MODEL_PATH)
    
    return metrics

def load_models():
    """Loads the pre-trained ensemble models."""
    if not os.path.exists(RF_MODEL_PATH) or not os.path.exists(ISO_MODEL_PATH):
        return train_base_model()
    return joblib.load(RF_MODEL_PATH), joblib.load(ISO_MODEL_PATH)

def predict(features_array):
    """
    Feeds features into the Ensemble Model (RF + Isolation Forest).
    """
    rf, iso = load_models()
    
    feature_arr = np.array([features_array])
    
    rf_label = rf.predict(feature_arr)[0]
    probabilities = rf.predict_proba(feature_arr)[0]
    rf_confidence = float(probabilities[rf_label])
    
    iso_prediction = iso.predict(feature_arr)[0]
    
    feature_names = [
        'entropy', 'length', 'subdomain_length', 'ngram_score', 'frequency', 
        'consonant_ratio', 'digit_ratio', 'unique_char', 'vowels_consonant_ratio',
        'max_continuous_numeric_len', 'max_continuous_alphabet_len', 
        'max_continuous_consonants_len', 'max_continuous_same_char',
        'upper_count', 'lower_count', 'special_count', 'labels', 'labels_max', 'labels_average',
        'entropy_to_length_ratio', 'high_entropy_flag', 'domain_complexity'
    ]
    
    shap_text = ""
    # Only run heavy SHAP explainer if classified as malicious or anomaly, for performance
    if rf_label == 1 or iso_prediction == -1:
        shap_text = get_shap_explanation(rf, features_array, feature_names)
        
    return int(rf_label), rf_confidence, int(iso_prediction), shap_text
