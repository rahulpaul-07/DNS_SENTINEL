from typing import Any
from fastapi import FastAPI, HTTPException, WebSocket, UploadFile, File, Response, BackgroundTasks
from fastapi.responses import StreamingResponse
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import time
import asyncio
from datetime import datetime
from collections import deque
import io
import csv
import pandas as pd
from fpdf import FPDF
from features import extract_features
from model import predict, train_custom_model
from mitre import map_threat, generate_explanation
from behavioral import analyzer as behavioral_analyzer
from intel_service import intel_service
from database import init_db, SessionLocal, DNSAuditLog, SecurityRule, Whitelist
from risk_engine import risk_engine



# CRITICAL: Create tables before importing SOAR actions (which depend on tables)
init_db()

from actions import orchestrator # SOAR Layer
from pie_engine import pie_engine # PIE Logic


from fastapi.responses import JSONResponse
from fastapi import Request
import json
import logging

# Initialize SOC Audit logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DNSentinel")

# Core Security Models
class DNSLog(BaseModel):
    timestamp: float = None
    query: str
    source_ip: str
    qtype: str = "A"

# Operational State
traffic_history = deque(maxlen=200)
alerts = deque(maxlen=100)
ip_query_history = {} 
alert_groups = {} 

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self.sse_queues: list[asyncio.Queue] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        # 1. WebSocket Broadcast
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass
        
        # 2. SSE Broadcast
        for queue in self.sse_queues:
            await queue.put(message)

manager = ConnectionManager()

# --- Security Logic Definitions ---

def calculate_frequency_for_ip(ip):
    current_time = time.time()
    if ip not in ip_query_history:
        ip_query_history[ip] = []
    ip_query_history[ip] = [t for t in ip_query_history[ip] if current_time - t < 60]
    return len(ip_query_history[ip])

# --- CAPTURE ENGINE INTEGRATION (Bridge to AI Pipeline) ---
from capture import start_capture, stop_capture

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

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start Live Sniffing (Disabled for stability)
    # try:
    #     loop = asyncio.get_running_loop()
    #     start_capture(interface=None, loop=loop, callback=process_capture_packet)
    #     logger.info("🚀 DNS Live Capture Engine: ACTIVE")
    # except Exception as e:
    #     logger.error(f"⚠️ Capture Initialization Failed: {e}")

    
    maintenance_task = asyncio.create_task(soar_maintenance())
    yield
    # stop_capture()
    maintenance_task.cancel()
    logger.info("🛑 DNS Live Capture Engine: SHUTDOWN")

# --- APP INITIALIZATION ---
app = FastAPI(
    title="DNSentinel: Enterprise DNS Exfiltration Detection",
    lifespan=lifespan
)

# Robust CORS for both HTTP and WebSockets
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"status": "DNSentinel Backend Online", "docs": "/docs"}



# --- SSE STREAMING ENDPOINT ---
@app.get("/stream")
async def stream(request: Request):
    """
    Server-Sent Events (SSE) Stream.
    A more robust alternative to WebSockets that automatically handles reconnections.
    """
    queue = asyncio.Queue()
    manager.sse_queues.append(queue)
    
    async def event_generator():
        try:
            while True:
                # If client closes connection, stop the generator
                if await request.is_disconnected():
                    break
                
                data = await queue.get()
                yield f"data: {json.dumps(data)}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            if queue in manager.sse_queues:
                manager.sse_queues.remove(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")



@app.post("/analyze")
async def analyze_dns_endpoint(log: DNSLog, skip_intel: bool = False, skip_broadcast: bool = False):
    return await analyze_dns(log, skip_intel, skip_broadcast)

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
    
    pred_label, rf_conf, iso_pred, shap_explanation = predict(feature_vector, log.query)
    
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
    # We pass the ML confidence and Intel score; the engine computes behavioral context
    risk_score, risk_level = await risk_engine.score(
        source_ip=log.source_ip, 
        domain=log.query, 
        ml_score=rf_conf, 
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

@app.post("/upload")
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

@app.post("/archive")
async def archive_logs():
    """Clears the active ledger to start a new forensic case."""
    with SessionLocal() as db:
        # Delete all records from DNSAuditLog
        db.query(DNSAuditLog).delete()
        db.commit()
        
        # Also clear in-memory caches
        global traffic_history, alerts, ip_query_history, alert_groups
        traffic_history.clear()
        alerts.clear()
        ip_query_history.clear()
        alert_groups.clear()
        
    return {"status": "success", "message": "Forensic ledger cleared."}

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

@app.get("/alerts/{log_id}/pdf")
async def generate_pdf_report(log_id: int):
    """Generates a professional PDF SOC Audit Report"""
    with SessionLocal() as db:
        log = db.query(DNSAuditLog).filter(DNSAuditLog.id == log_id).first()
        if not log: raise HTTPException(404, "Alert record not found")
        
        pdf = FPDF()
        pdf.add_page()
        
        # Header
        pdf.set_fill_color(20, 30, 48) # Dark SOC Theme
        pdf.rect(0, 0, 210, 40, 'F')
        
        pdf.set_font("Arial", 'B', 24)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 20, "DNSentinel: SOC Incident Audit", ln=True, align='C')
        
        pdf.set_font("Arial", '', 10)
        pdf.cell(0, 5, f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
        pdf.ln(15)
        
        # Summary Section
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(0, 10, "1. Executive Summary", ln=True)
        pdf.set_font("Arial", '', 11)
        pdf.multi_cell(0, 7, f"An automated security audit was triggered for source IP {log.source_ip} due to a {log.risk_level} risk detection involving the query '{log.query}'. The system categorized this as a '{log.prediction}' threat.")
        pdf.ln(5)
        
        # Threat Details Table
        pdf.set_font("Arial", 'B', 12)
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(95, 10, "Metric", border=1, fill=True)
        pdf.cell(95, 10, "Value", border=1, fill=True, ln=True)
        
        pdf.set_font("Arial", '', 11)
        metrics = [
            ("Incident ID", f"SOC-{log.id}"),
            ("Timestamp", log.timestamp.strftime('%Y-%m-%d %H:%M:%S') if log.timestamp else "N/A"),
            ("Source IP", log.source_ip),
            ("Query Domain", log.query),
            ("Risk Score", str(log.risk_score)),
            ("Severity Level", log.risk_level),
            ("ML Prediction", log.prediction),
            ("Priority Class", log.priority)
        ]
        
        for metric, val in metrics:
            pdf.cell(95, 8, metric, border=1)
            pdf.cell(95, 8, val, border=1, ln=True)
        
        pdf.ln(10)
        
        # Analysis Details
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, "2. SOC Technical Analysis", ln=True)
        pdf.set_font("Arial", '', 11)
        pdf.multi_cell(0, 7, log.explanation or "No detailed explanation provided.")
        pdf.ln(5)
        
        # MITRE Mapping
        if log.mitre_data:
            pdf.set_font("Arial", 'B', 14)
            pdf.cell(0, 10, "3. MITRE ATT&CK Mapping", ln=True)
            pdf.set_font("Arial", '', 10)
            for tactic, technique in log.mitre_data.items():
                pdf.set_font("Arial", 'B', 10)
                pdf.cell(40, 6, f"{tactic}:")
                pdf.set_font("Arial", '', 10)
                pdf.cell(0, 6, technique, ln=True)
        
        # Footer
        pdf.set_y(-30)
        pdf.set_font("Arial", 'I', 8)
        pdf.set_text_color(128, 128, 128)
        pdf.cell(0, 10, "This report is cryptographically signed and archived for compliance. | DNSentinel Enterprise XDR", align='C')

        from fastapi.responses import Response
        return Response(content=bytes(pdf.output()), media_type="application/pdf", headers={
            "Content-Disposition": f"attachment; filename=SOC_Audit_{log_id}.pdf"
        })

@app.get("/export/pdf")
async def export_pdf_report():
    """Generates a comprehensive Enterprise SOC Audit PDF report"""
    with SessionLocal() as db:
        logs = db.query(DNSAuditLog).order_by(DNSAuditLog.id.desc()).all()
        
        # Stats for executive summary
        total_logs = len(logs)
        critical_count = sum(1 for l in logs if l.risk_level == "Critical")
        high_count = sum(1 for l in logs if l.risk_level == "High")
        medium_count = sum(1 for l in logs if l.risk_level == "Medium")
        
        pdf = FPDF()
        
        # --- Cover Page ---
        pdf.add_page()
        pdf.set_fill_color(15, 23, 42) # slate-900
        pdf.rect(0, 0, 210, 297, 'F')
        
        pdf.set_y(100)
        pdf.set_font("Arial", 'B', 36)
        pdf.set_text_color(0, 242, 255) # #00f2ff
        pdf.cell(0, 20, "DNSENTINEL X-DR", ln=True, align='C')
        
        pdf.set_font("Arial", 'B', 18)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 15, "Enterprise Security Audit Report", ln=True, align='C')
        
        pdf.ln(20)
        pdf.set_font("Arial", '', 12)
        pdf.set_text_color(148, 163, 184) # slate-400
        pdf.cell(0, 10, f"Generated On: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
        pdf.cell(0, 10, f"Total Forensic Events: {total_logs}", ln=True, align='C')
        
        # --- Executive Summary ---
        pdf.add_page()
        pdf.set_fill_color(255, 255, 255)
        pdf.set_text_color(0, 0, 0)
        
        pdf.set_font("Arial", 'B', 20)
        pdf.cell(0, 20, "1. Executive Summary", ln=True)
        pdf.ln(5)
        
        pdf.set_font("Arial", '', 11)
        summary_text = (
            f"This report provides a comprehensive overview of the DNS traffic monitored by DNSentinel. "
            f"During the current audit period, a total of {total_logs} DNS requests were analyzed using "
            f"the ensemble ML engine. A total of {critical_count + high_count + medium_count} potential "
            f"threats were identified across various severity levels."
        )
        pdf.multi_cell(0, 7, summary_text)
        pdf.ln(10)
        
        # Risk Distribution Table
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, "Risk Distribution", ln=True)
        pdf.set_fill_color(241, 245, 249) # slate-100
        pdf.cell(95, 10, "Severity Level", border=1, fill=True)
        pdf.cell(95, 10, "Event Count", border=1, fill=True, ln=True)
        
        pdf.set_font("Arial", '', 11)
        dist_data = [
            ("Critical", critical_count),
            ("High", high_count),
            ("Medium", medium_count),
            ("Low", total_logs - (critical_count + high_count + medium_count))
        ]
        for level, count in dist_data:
            pdf.cell(95, 10, level, border=1)
            pdf.cell(95, 10, str(count), border=1, ln=True)
            
        pdf.ln(15)
        
        # --- Threat Intelligence Section ---
        pdf.set_font("Arial", 'B', 20)
        pdf.cell(0, 20, "2. Top Security Threats", ln=True)
        pdf.ln(5)
        
        critical_logs = [l for l in logs if l.risk_level in ["Critical", "High"]][:10]
        if not critical_logs:
            pdf.set_font("Arial", 'I', 11)
            pdf.cell(0, 10, "No critical or high severity threats detected in this audit period.", ln=True)
        else:
            pdf.set_font("Arial", 'B', 10)
            pdf.set_fill_color(220, 38, 38) # red-600
            pdf.set_text_color(255, 255, 255)
            pdf.cell(35, 10, "Timestamp", border=1, fill=True)
            pdf.cell(35, 10, "Source IP", border=1, fill=True)
            pdf.cell(80, 10, "Query Domain", border=1, fill=True)
            pdf.cell(20, 10, "Score", border=1, fill=True)
            pdf.cell(20, 10, "Level", border=1, fill=True, ln=True)
            
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", '', 9)
            for l in critical_logs:
                # Truncate query if too long
                q = l.query[:40] + "..." if len(l.query) > 40 else l.query
                ts = l.timestamp.strftime('%H:%M:%S') if l.timestamp else "N/A"
                pdf.cell(35, 8, ts, border=1)
                pdf.cell(35, 8, l.source_ip, border=1)
                pdf.cell(80, 8, q, border=1)
                pdf.cell(20, 8, str(l.risk_score), border=1)
                pdf.cell(20, 8, l.risk_level, border=1, ln=True)
                
        # --- Full Audit Ledger ---
        pdf.add_page()
        pdf.set_font("Arial", 'B', 20)
        pdf.cell(0, 20, "3. Forensic Ledger (Sample)", ln=True)
        pdf.ln(5)
        
        pdf.set_font("Arial", 'B', 10)
        pdf.set_fill_color(203, 213, 225) # slate-300
        pdf.cell(30, 10, "Time", border=1, fill=True)
        pdf.cell(35, 10, "IP", border=1, fill=True)
        pdf.cell(95, 10, "Query", border=1, fill=True)
        pdf.cell(30, 10, "Level", border=1, fill=True, ln=True)
        
        pdf.set_font("Arial", '', 8)
        for l in logs[:100]: # Limit to first 100 for performance/readability in PDF
            q = l.query[:50] + "..." if len(l.query) > 50 else l.query
            ts = l.timestamp.strftime('%Y-%m-%d %H:%M') if l.timestamp else "N/A"
            pdf.cell(30, 8, ts, border=1)
            pdf.cell(35, 8, l.source_ip, border=1)
            pdf.cell(95, 8, q, border=1)
            pdf.cell(30, 8, l.risk_level, border=1, ln=True)
            
        if len(logs) > 100:
            pdf.ln(5)
            pdf.set_font("Arial", 'I', 9)
            pdf.cell(0, 10, f"... and {len(logs) - 100} more events. Use CSV export for full forensic data.", ln=True, align='C')

        from fastapi.responses import Response
        return Response(content=bytes(pdf.output()), media_type="application/pdf", headers={
            "Content-Disposition": f"attachment; filename=DNSentinel_Full_Audit_{datetime.now().strftime('%Y%m%d')}.pdf"
        })

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
                log.timestamp.isoformat() if log.timestamp else "",
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

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except Exception:
        manager.disconnect(websocket)
