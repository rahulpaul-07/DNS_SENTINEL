from fastapi import FastAPI, HTTPException, WebSocket, UploadFile, File, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import time
import asyncio
from datetime import datetime
from collections import deque
import io
import csv
import pandas as pd
from sqlalchemy.orm import Session

from features import extract_features
from model import predict, train_custom_model
from mitre import map_threat, generate_explanation
from behavioral import analyzer as behavioral_analyzer
from intel_service import intel_service
from database import init_db, SessionLocal, DNSAuditLog, SecurityRule, Whitelist
# CRITICAL: Create tables before importing SOAR actions (which depend on tables)
init_db()

from actions import orchestrator # SOAR Layer
from pie_engine import pie_engine # PIE Logic

from fastapi.responses import JSONResponse
from fastapi import Request
import logging

# Initialize SOC Audit logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DNSentinel")

# SOC Security Engine: Operational
app = FastAPI(title="DNSentinel: Enterprise DNS Exfiltration Detection")

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"🚨 CRITICAL_SERVER_FAULT: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"message": "Internal SOAR Orchestration Fault", "details": str(exc)}
    )

async def soar_maintenance():
    """Background task for auto-cleanup of security rules"""
    while True:
        orchestrator.cleanup_expired_rules()
        await asyncio.sleep(60)

@app.on_event("startup")
async def on_startup():
    asyncio.create_task(soar_maintenance())

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

# Open-Gate Dev CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

traffic_history = deque(maxlen=200)
alerts = deque(maxlen=100)
ip_query_history = {} 
alert_groups = {} # SOC Correlation logic
class DNSLog(BaseModel):
    timestamp: float = None
    query: str
    source_ip: str
    qtype: str = "A"

def calculate_frequency_for_ip(ip):
    current_time = time.time()
    if ip not in ip_query_history:
        ip_query_history[ip] = []
    ip_query_history[ip] = [t for t in ip_query_history[ip] if current_time - t < 60]
    return len(ip_query_history[ip])

@app.get("/")
async def root():
    return {"status": "DNSentinel Backend Online", "docs": "/docs"}

@app.post("/analyze")
async def analyze_dns(log: DNSLog, skip_intel: bool = False, skip_broadcast: bool = False):
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
    
    pred_label, rf_conf, iso_pred, shap_explanation = predict(feature_vector)
    
    # 4. Realistic Risk Scoring Engine (Normalize 0-100)
    # ML base weight
    risk_score = 0
    if pred_label == 1:
        risk_score += (rf_conf * 60) # Supervised confidence yields max 60 points
    else:
        risk_score += (rf_conf * 10) # Even if classified normal, if borderline, small bump
        
    # Anomaly bump
    if iso_pred == -1:
         risk_score += 25 # Unsupervised anomaly yields 25 points
         
    # Extreme Heuristic Overrides
    if features['entropy'] > 4.2:
         risk_score += 15
    if features['ngram_score'] < 0.005:
         risk_score += 15
    if log.qtype == "TXT" and features['length'] > 40:
         risk_score += 25 # TXT queries transferring huge blocks is massive exfil red flag
    
    # 3b. Real-Time Threat Intelligence Enrichment (Async)
    intel_hit = False
    if not skip_intel:
        intel_data = await intel_service.enrich_query(log.query, log.source_ip)
        risk_score += intel_data['reputation_score']
        features['intel_data'] = intel_data
        intel_hit = intel_data['is_malicious']
    else:
        # Fast local fallback for bulk ingest
        local_intel = intel_service.check_local_heuristics(log.query)
        risk_score += local_intel['score']
        features['intel_data'] = {"sources": ["Local Heuristics"], "threat_tags": local_intel['tags'], "reputation_score": local_intel['score']}
        intel_hit = local_intel['score'] > 30

    # Behavioral Influence
    risk_score += behavior['behavior_score']
         
    risk_score = min(risk_score, 100) # Cap at 100
    
    # 4-Tier Severity Categorization
    risk_level = "Low"
    if risk_score >= 80: risk_level = "Critical"
    elif risk_score >= 50: risk_level = "High"
    elif risk_score >= 25: risk_level = "Medium"
    
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
        "confidence": rf_conf,
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
    
    # 6B. Calculate PIE (Priority Intelligence Engine) Result
    # (Mocking asset_value and intel_score for the demo; will use real Lookups in prod)
    pie_result = pie_engine.calculate_priority(
        risk_score=risk_score,
        intel_score=95 if intel_hit else (40 if is_malicious else 5),
        asset_value=85 if ".domain.local" in log.query else 50,
        behavior_score=75 if log.source_ip in behavioral_analyzer.anomalies else 0,
        attack_type=analysis_result['prediction'].split(" ")[0].lower() or "normal"
    )
    
    analysis_result.update(pie_result)
    
    # 7. Forensic Data Persistence (SQL)
    new_log = DNSAuditLog(
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
        explanation=analysis_result['explanation']
    )
    
    # Use shared session if provided
    active_db = db or SessionLocal()
    try:
        active_db.add(new_log)
        active_db.commit()
        active_db.refresh(new_log)
        analysis_result['db_id'] = new_log.id

        # --- Automated SOAR Response ---
        if risk_score > orchestrator.AUTO_BLOCK_THRESHOLD and (intel_hit or isolation_outlier):
            orchestrator.trigger_block(
                entity=log.source_ip, 
                reason=f"Zero-Touch Automated Containment: {explanation.split('|')[0]}",
                rule_type="IP_BLOCK",
                risk_score=risk_score
            )
            new_log.is_blocked = True
            active_db.commit()
    finally:
        if not db: active_db.close()

    if not skip_broadcast:
        await manager.broadcast(analysis_result)
    return analysis_result

@app.post("/upload")
async def upload_csv(file: UploadFile = File(...)):
    """Transactional Bulk Ingest: Handles datasets within a single high-perf connection"""
    contents = await file.read()
    decoded = contents.decode('utf-8', errors='ignore') 
    lines = decoded.splitlines()
    
    db_session = SessionLocal()
    analyzed_count = 0
    threats_found = 0
    
    try:
        if len(lines) > 0 and lines[0].startswith("#separator"):
            for line in lines:
                if line.startswith("#"): continue
                parts = line.split('\t')
                if len(parts) > 13:
                    log = DNSLog(query=parts[9], source_ip=parts[2], qtype=parts[13], timestamp=time.time())
                    res = await analyze_dns(log, skip_intel=True, skip_broadcast=True, db=db_session)
                    analyzed_count += 1
                    if res['risk_level'] in ['Critical', 'High', 'Medium']: threats_found += 1
        else:
            reader = csv.DictReader(io.StringIO(decoded))
            for row in reader:
                # 1. Resolve Query (Fuzzy Match)
                q = None
                for col in ['query', 'domain', 'dns_domain_name', 'hostname', 'url']:
                    if col in row and row[col]:
                        q = row[col]
                        break
                
                if not q: continue
                
                # 2. Resolve IP
                ip = row.get('source_ip', row.get('src_ip', row.get('ip', '0.0.0.0')))
                
                # 3. Type
                qtype = row.get('qtype', row.get('query_type', 'A'))
                
                log = DNSLog(query=q, source_ip=ip, qtype=qtype, timestamp=time.time())
                # Live Broadcast every 20th log to keep dashboard 'alive' during demo
                broadcast_toggle = (analyzed_count % 20 == 0)
                res = await analyze_dns(log, skip_intel=True, skip_broadcast=not broadcast_toggle, db=db_session)
                analyzed_count += 1
                if res['risk_level'] in ['Critical', 'High', 'Medium']: threats_found += 1
        
        return {"message": f"Successfully evaluated {analyzed_count} logs. Total threats: {threats_found}", "processed": analyzed_count}
    finally:
        db_session.close()

@app.post("/train")
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

@app.get("/alerts")
async def get_alerts(response: Response, limit: int = 50):
    """Fetches alerts from the ledger. Cache-Control: no-store enforces freshness."""
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    with SessionLocal() as db:
        logs = db.query(DNSAuditLog).filter(DNSAuditLog.risk_level != "Low").order_by(DNSAuditLog.id.desc()).limit(limit).all()
        return [{
            "db_id": l.id,
            "timestamp": (l.timestamp.isoformat() if l.timestamp and hasattr(l.timestamp, 'isoformat') else str(l.timestamp or "")),
            "source_ip": l.source_ip,
            "query": l.query,
            "qtype": l.qtype,
            "risk_score": l.risk_score,
            "risk_level": l.risk_level,
            "priority": l.priority,
            "priority_score": l.priority_score,
            "prediction": l.prediction,
            "mitre": l.mitre_data,
            "features": l.features,
            "explanation": l.explanation
        } for l in logs]

@app.get("/traffic")
async def get_traffic(response: Response, limit: int = 100):
    """Pulls records from persistence. Cache-Control: no-store prevents 'Ghost Data' on refresh."""
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    with SessionLocal() as db:
        logs = db.query(DNSAuditLog).order_by(DNSAuditLog.id.desc()).limit(limit).all()
        return [{
            "db_id": l.id,
            "timestamp": (l.timestamp.isoformat() if l.timestamp and hasattr(l.timestamp, 'isoformat') else str(l.timestamp or "")),
            "source_ip": l.source_ip,
            "query": l.query,
            "qtype": l.qtype,
            "risk_score": l.risk_score,
            "risk_level": l.risk_level,
            "priority": l.priority,
            "priority_score": l.priority_score,
            "prediction": l.prediction,
            "mitre": l.mitre_data,
            "features": l.features,
            "explanation": l.explanation
        } for l in logs]

# --- SOC / SOAR Action Endpoints ---

@app.post("/alerts/{log_id}/block")
async def block_host(log_id: int):
    """SOAR Action: Real firewall orchestration for manual block"""
    with SessionLocal() as db:
        log = db.query(DNSAuditLog).filter(DNSAuditLog.id == log_id).first()
        if not log: raise HTTPException(404, "Log not found")
        
        result = orchestrator.trigger_block(
            entity=log.source_ip, 
            reason=f"Manual SOC Alert Block: {log.id}",
            rule_type="IP_BLOCK",
            risk_score=log.risk_score
        )
        log.is_blocked = True
        db.commit()
        return result

@app.post("/unblock/{entity}")
async def unblock_entity(entity: str):
    """Manual analyst override to unblock an IP/Domain"""
    return orchestrator.trigger_unblock(entity)

@app.get("/blocked")
async def list_blocked_entities():
    """Returns a list of all currently active SOAR blocks"""
    with SessionLocal() as db:
        return db.query(SecurityRule).filter(SecurityRule.is_active == True).all()

@app.post("/alerts/{log_id}/feedback")
async def log_feedback(log_id: int):
    """Human-in-the-loop: Analyst marked as False Positive/Benign"""
    return orchestrator.mark_false_positive(log_id)

@app.get("/alerts/{log_id}/report")
async def generate_report(log_id: int):
    """Automated IR Report Generation"""
    report = orchestrator.generate_incident_report(log_id)
    if not report: raise HTTPException(404, "Case index not found")
    return {"markdown": report}

@app.get("/export")
async def export_logs():
    """Generates a full forensic CSV export from the persistent database ledger"""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['timestamp', 'source_ip', 'query', 'qtype', 'risk_score', 'risk_level', 'mitre_ids'])
    
    with SessionLocal() as db:
        logs = db.query(DNSAuditLog).all()
        for log in logs:
            writer.writerow([
                log.timestamp.isoformat(),
                log.source_ip,
                log.query,
                log.qtype,
                log.risk_score,
                log.risk_level,
                ", ".join(log.mitre_data.keys()) if log.mitre_data else ""
            ])
    
    return {"csv": output.getvalue()}

@app.post("/archive")
async def archive_and_clear():
    """Performs a full forensic wipe of the active dashboard state"""
    with SessionLocal() as db:
        # Atomic wipe of audit ledger to ensure blank page on refresh
        from sqlalchemy import delete
        db.execute(delete(DNSAuditLog))
        db.execute(delete(SecurityRule))
        db.commit()
    
    # Hard-Reset in-memory deques
    traffic_history.clear()
    alerts.clear()
    alert_groups.clear()
    
    return {"status": "SUCCESS", "message": "Forensic ledger truncated. Environment is now blank."}

@app.get("/stats")
async def get_stats():
    """Calculates enterprise-wide SOC statistics from the historical database"""
    with SessionLocal() as db:
        total = db.query(DNSAuditLog).count()
        if total == 0:
            return {
                "total_requests": 0, "total_alerts": 0, "avg_frequency": 0, "avg_entropy": 0,
                "risk_distribution": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            }

        critical = db.query(DNSAuditLog).filter(DNSAuditLog.risk_level == "Critical").count()
        high = db.query(DNSAuditLog).filter(DNSAuditLog.risk_level == "High").count()
        medium = db.query(DNSAuditLog).filter(DNSAuditLog.risk_level == "Medium").count()
        low = db.query(DNSAuditLog).filter(DNSAuditLog.risk_level == "Low").count()

        return {
            "total_requests": total,
            "total_alerts": critical + high + medium,
            "risk_distribution": {
                "Critical": critical,
                "High": high,
                "Medium": medium,
                "Low": low
            }
        }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except Exception:
        manager.disconnect(websocket)
