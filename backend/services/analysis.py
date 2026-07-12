"""Core detection pipeline + background workers (extracted from main.py).

analyze_dns is the heart of the service: feature extraction -> ML ensemble ->
adaptive risk scoring -> MITRE mapping -> PIE prioritization -> persistence ->
SOAR auto-response -> live broadcast. Kept behaviour-identical to the original
monolith; only the module location changed.
"""
import asyncio
from typing import Any
import csv
import io
import logging
import time
from datetime import datetime

from features import extract_features
from model import predict
from mitre import map_threat, generate_explanation
from behavioral import analyzer as behavioral_analyzer
from intel_service import intel_service
from database import SessionLocal, DNSAuditLog
from risk_engine import risk_engine
from actions import orchestrator
from pie_engine import pie_engine

from schemas import DNSLog
from state import (
    traffic_history, alerts, ip_query_history, alert_groups,
    manager, calculate_frequency_for_ip,
)

logger = logging.getLogger("DNSentinel")


async def process_capture_packet(event: dict):
    """Bridge: Feeds raw captured packets into the AI Analysis Engine"""
    try:
        log_data = DNSLog(
            query=event.get("query_name", "unknown"),
            source_ip=event.get("src_ip", "0.0.0.0"),
            qtype=event.get("query_type", "A")
        )
        await analyze_dns(log_data)
    except Exception as e:
        logger.error(f"Live Analysis Bridge Error: {e}")


async def analyze_dns(log: DNSLog, skip_intel: bool = False, skip_broadcast: bool = False, db: Any = None):
    if not log.timestamp:
        log.timestamp = time.time()

    # 1. Behavioral Tracker
    ip_query_history[log.source_ip] = ip_query_history.get(log.source_ip, []) + [log.timestamp]
    frequency = calculate_frequency_for_ip(log.source_ip)

    # 2. Extract Structural Features
    features = extract_features(log.dict())
    features['frequency'] = frequency # Add Temporal Feature

    # 3. Model Prediction Engine (Random Forest + Isolation Forest)
    # 19 parameters
    feature_vector = [
        features['entropy'],
        features['length'],
        features['subdomain_length'],
        features['ngram_score'],
        frequency,
        features['consonant_ratio'],
        features['digit_ratio'],
        features['unique_char'],
        features['vowels_consonant_ratio'],
        features['max_continuous_numeric_len'],
        features['max_continuous_alphabet_len'],
        features['max_continuous_consonants_len'],
        features['max_continuous_same_char'],
        features['upper_count'],
        features['lower_count'],
        features['special_count'],
        features['labels'],
        features['labels_max'],
        features['labels_average'],
        features['entropy_to_length_ratio'],
        features['high_entropy_flag'],
        features['domain_complexity']
    ]

    # 3. Behavioral Analysis (Zero-Day & Velocity Detection)
    behavior = behavioral_analyzer.analyze(log.source_ip, log.query)
    features['behavioral_metrics'] = behavior

    pred_label, mal_prob, iso_pred, shap_explanation = predict(feature_vector, log.query)

    # 4. Adaptive Risk Scoring Engine (Context-Aware)
    intel_score = 0.0
    intel_hit = False

    if not skip_intel:
        intel_data = await intel_service.enrich_query(log.query, log.source_ip)
        intel_score = intel_data.get('reputation_score', 0) / 100.0 # Normalize to 0-1
        features['intel_data'] = intel_data
        intel_hit = intel_data.get('is_malicious', False)
    else:
        local_intel = intel_service.check_local_heuristics(log.query)
        intel_score = local_intel.get('score', 0) / 100.0
        features['intel_data'] = {"sources": ["Local Heuristics"], "threat_tags": local_intel['tags'], "reputation_score": local_intel['score']}
        intel_hit = local_intel.get('score', 0) > 30

    # Calculate final score using Adaptive Engine
    # Pass the ML malicious probability (not label-confidence) so higher = riskier.
    risk_score, risk_level = await risk_engine.score(
        source_ip=log.source_ip,
        domain=log.query,
        ml_score=mal_prob,
        intel_score=intel_score
    )

    # 5. MITRE Mapping & SOC Explainability
    mitre_tags = map_threat(features, pred_label, iso_pred)
    explanation = generate_explanation(features, pred_label, iso_pred, risk_score)

    analysis_result = {
        "timestamp": datetime.fromtimestamp(log.timestamp).isoformat(),
        "query": log.query,
        "qtype": log.qtype,
        "source_ip": log.source_ip,
        "features": features,
        "prediction": "Malicious" if (pred_label == 1 or risk_level in ["Critical", "High", "Medium"]) else "Normal",
        "confidence": round(mal_prob if pred_label == 1 else 1 - mal_prob, 3),
        "risk_score": round(risk_score, 1),
        "risk_level": risk_level,
        "isolation_outlier": iso_pred == -1,
        "behavioral_flags": {
            "burst": behavior['burst_detected'],
            "structured": behavior['structured_burst']
        },
        "intel_hit": intel_hit,
        "mitre": mitre_tags,
        "explanation": f"{explanation} | {shap_explanation}" if shap_explanation else explanation
    }

    # 6. SOC Alert Correlation Logic
    if risk_level in ["Critical", "High", "Medium"]:
        agg_key = f"{log.source_ip}"
        now = time.time()

        if agg_key not in alert_groups or (now - alert_groups[agg_key]['last_seen'] > 600):
            alert_groups[agg_key] = {
                "id": f"ALERT-{int(now)}",
                "source_ip": log.source_ip,
                "severity": risk_level,
                "first_seen": now,
                "last_seen": now,
                "count": 1,
                "domains": [log.query]
            }
            alerts.append(analysis_result)
        else:
            alert_groups[agg_key]['last_seen'] = now
            alert_groups[agg_key]['count'] += 1
            if log.query not in alert_groups[agg_key]['domains']:
                alert_groups[agg_key]['domains'].append(log.query)
            # Only push the highest severity logic here or similar correlation strategy
            if risk_level == "Critical": alerts.append(analysis_result)

    traffic_history.append(analysis_result)

    detailed_explanation = analysis_result.get("explanation", "")

    # 6B. Calculate PIE (Priority Intelligence Engine) Result
    # (Mocking asset_value and intel_score for the demo; will use real Lookups in prod)
    pie_result = pie_engine.calculate_priority(
        risk_score=risk_score,
        intel_score=95 if intel_hit else (40 if pred_label == 1 else 5),
        asset_value=85 if ".domain.local" in log.query else 50,
        behavior_score=behavior['behavior_score'],
        attack_type=analysis_result['prediction'].split(" ")[0].lower() or "normal"
    )

    pie_explanation = pie_result.pop("explanation", "")
    analysis_result.update(pie_result)

    if detailed_explanation and pie_explanation:
        analysis_result["explanation"] = f"{detailed_explanation} | {pie_explanation}"
    elif detailed_explanation:
        analysis_result["explanation"] = detailed_explanation
    else:
        analysis_result["explanation"] = pie_explanation

    # 7. Forensic Data Persistence (SQL)
    active_db = db or SessionLocal()
    try:
        new_record = DNSAuditLog(
            source_ip=log.source_ip,
            query=log.query,
            qtype=log.qtype,
            risk_score=analysis_result['risk_score'],
            risk_level=analysis_result['risk_level'],
            prediction=analysis_result['prediction'],
            priority=pie_result['priority'],
            priority_score=pie_result['priority_score'],
            mitre_data=analysis_result['mitre'],
            features=features,
            explanation=analysis_result['explanation'],
            timestamp=datetime.fromtimestamp(log.timestamp)
        )
        active_db.add(new_record)
        active_db.commit()
        active_db.refresh(new_record)
        analysis_result['db_id'] = new_record.id

        # --- Simple Automated Response ---
        if risk_score > 80:
            # Note: orchestrator has its own internal DB session,
            # but we can pass one if we update actions.py. For now, it uses its own.
            response = orchestrator.trigger_block(
                entity=log.source_ip,
                reason=f"High Risk Score ({risk_score}) for {log.query}"
            )
            analysis_result['soar_action'] = response

        if not skip_broadcast:
            await manager.broadcast(analysis_result)

        return analysis_result
    except Exception as e:
        logger.error(f"❌ Persistence Error: {e}")
        return analysis_result
    finally:
        if not db: active_db.close()


async def process_csv_background(decoded_content: str):
    """Bulletproof background worker with enhanced logging"""
    print(f"[*] Background Ingest Started. Content Length: {len(decoded_content)}")
    try:
        lines = decoded_content.splitlines()
        with SessionLocal() as db_session:
            if len(lines) > 0 and lines[0].startswith("#separator"):
                print("[*] Detected Zeek/TSV format")
                for line in lines:
                    if line.startswith("#"): continue
                    parts = line.split('\t')
                    if len(parts) > 13:
                        log = DNSLog(query=parts[9], source_ip=parts[2], qtype=parts[13], timestamp=time.time())
                        await analyze_dns(log, skip_intel=True, skip_broadcast=False, db=db_session)
                        await asyncio.sleep(0.01)
            else:
                print("[*] Detected Standard CSV format")
                reader = csv.DictReader(io.StringIO(decoded_content))
                count = 0
                for row in reader:
                    q = None
                    for col in ['query', 'domain', 'dns_domain_name', 'hostname', 'url']:
                        if col in row: q = row[col]; break

                    if not q:
                        continue

                    src = row.get('source_ip') or row.get('src_ip') or row.get('client_ip') or '0.0.0.0'
                    qt = row.get('qtype') or row.get('type') or 'A'

                    log = DNSLog(query=q, source_ip=src, qtype=qt, timestamp=time.time())
                    await analyze_dns(log, skip_intel=True, skip_broadcast=False, db=db_session)
                    count += 1
                    if count % 10 == 0: print(f"[*] Processed {count} rows...")
                    await asyncio.sleep(0.02) # Higher sleep for stability
        print(f"✅ Background Ingest Finished Successfully. Processed {count} rows.")
    except Exception as e:
        print(f"❌ Background Ingest Crash: {e}")
        logger.error(f"Background Ingest Crash: {e}")


async def soar_maintenance():
    """Background task for auto-cleanup of security rules"""
    while True:
        orchestrator.cleanup_expired_rules()
        await asyncio.sleep(60)

