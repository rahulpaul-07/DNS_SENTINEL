"""Bulk ingest, model retraining, and forensic archive endpoints."""
import csv
import io
import logging

import pandas as pd
from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from features import extract_features
from model import train_custom_model
from database import SessionLocal, DNSAuditLog, SecurityRule
from services.analysis import process_csv_background
from state import traffic_history, alerts, ip_query_history, alert_groups

logger = logging.getLogger("DNSentinel")
router = APIRouter()


@router.post("/upload")
async def upload_csv(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """Safe Async Upload: Returns immediate JSON and runs task in background"""
    try:
        contents = await file.read()
        decoded = contents.decode('utf-8', errors='ignore')

        # Start background task AFTER defining it to ensure it's fully ready
        background_tasks.add_task(process_csv_background, decoded)

        return {
            "status": "success",
            "message": "Ingest started. You will see logs appearing live shortly."
        }
    except Exception as e:
        logger.error(f"Upload Setup Error: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


@router.post("/train")
async def train_model_endpoint(file: UploadFile = File(...)):
    """Trains the ML Engine natively and returns strict model evaluation metrics."""
    contents = await file.read()
    decoded = contents.decode('utf-8')
    reader = csv.DictReader(io.StringIO(decoded))

    dataset = []
    for row in reader:
        # Require 'query' and 'label'
        q = row.get('query', row.get('domain', ''))
        label_raw = row.get('label', row.get('is_dga', row.get('malicious', None)))
        ip = row.get('source_ip', '0.0.0.0')

        if not q or label_raw is None:
            continue

        try:
            if str(label_raw).lower() == 'malicious':
                label = 1
            elif str(label_raw).lower() == 'benign':
                label = 0
            else:
                label = int(label_raw)
        except ValueError:
            continue

        # Dynamically extract all features out of the query exactly as the real pipeline does
        log = {'query': q, 'source_ip': ip}
        features = extract_features(log)

        # Simulate temporal freq just for structural extraction parity
        features['frequency'] = 1

        dataset.append({
            'entropy': features['entropy'],
            'length': features['length'],
            'subdomain_length': features['subdomain_length'],
            'ngram_score': features['ngram_score'],
            'frequency': features['frequency'],
            'consonant_ratio': features['consonant_ratio'],
            'digit_ratio': features['digit_ratio'],
            'unique_char': features['unique_char'],
            'vowels_consonant_ratio': features['vowels_consonant_ratio'],
            'max_continuous_numeric_len': features['max_continuous_numeric_len'],
            'max_continuous_alphabet_len': features['max_continuous_alphabet_len'],
            'max_continuous_consonants_len': features['max_continuous_consonants_len'],
            'max_continuous_same_char': features['max_continuous_same_char'],
            'upper_count': features['upper_count'],
            'lower_count': features['lower_count'],
            'special_count': features['special_count'],
            'labels': features['labels'],
            'labels_max': features['labels_max'],
            'labels_average': features['labels_average'],
            'entropy_to_length_ratio': features['entropy_to_length_ratio'],
            'high_entropy_flag': features['high_entropy_flag'],
            'domain_complexity': features['domain_complexity'],
            'label': label
        })

    if not dataset:
        raise HTTPException(status_code=400, detail="No valid data points found. Make sure CSV has 'query' and 'label' columns.")

    try:
        df = pd.DataFrame(dataset)
        metrics = train_custom_model(df)
        return {"status": "success", "metrics": metrics, "rows_processed": len(dataset)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/archive")
async def archive_and_clear():
    """Performs a full forensic wipe of the active dashboard state"""
    with SessionLocal() as db:
        # Atomic wipe of audit ledger to ensure blank page on refresh
        from sqlalchemy import delete
        db.execute(delete(DNSAuditLog))
        db.execute(delete(SecurityRule))
        db.commit()

    # Hard-Reset in-memory deques / caches (single canonical /archive handler;
    # a duplicate route with the same path previously shadowed this one).
    global traffic_history, alerts, ip_query_history, alert_groups
    traffic_history.clear()
    alerts.clear()
    ip_query_history.clear()
    alert_groups.clear()

    return {"status": "SUCCESS", "message": "Forensic ledger truncated. Environment is now blank."}

