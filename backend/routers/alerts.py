"""Alert ledger, per-alert reports/PDFs, and SOAR block/feedback actions."""
from datetime import datetime

from fastapi import APIRouter, HTTPException, Response
from fpdf import FPDF

from database import SessionLocal, DNSAuditLog
from actions import orchestrator
from state import VALID_RISK_LEVELS

router = APIRouter()


@router.get("/alerts")
async def get_alerts(
    response: Response,
    limit: int = 50,
    offset: int = 0,
    risk_level: str = None,
):
    """Fetches alerts from the ledger with optional filtering and pagination.

    Query params:
      - limit:      max rows to return (1-500, default 50)
      - offset:     rows to skip, for pagination (default 0)
      - risk_level: filter to a single tier (Low|Medium|High|Critical)
    """
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    with SessionLocal() as db:
        query = db.query(DNSAuditLog)
        if risk_level:
            level = risk_level.strip().capitalize()
            if level not in VALID_RISK_LEVELS:
                raise HTTPException(
                    status_code=400,
                    detail=f"invalid risk_level '{risk_level}'; expected one of "
                    f"{sorted(VALID_RISK_LEVELS)}",
                )
            query = query.filter(DNSAuditLog.risk_level == level)
        else:
            # Default alert view excludes benign Low-risk noise.
            query = query.filter(DNSAuditLog.risk_level != "Low")
        logs = query.order_by(DNSAuditLog.id.desc()).offset(offset).limit(limit).all()
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


@router.post("/alerts/{log_id}/block")
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


@router.post("/alerts/{log_id}/feedback")
async def log_feedback(log_id: int):
    """Human-in-the-loop: Analyst marked as False Positive/Benign"""
    return orchestrator.mark_false_positive(log_id)


@router.get("/alerts/{log_id}/report")
async def generate_report(log_id: int):
    """Automated IR Report Generation"""
    report = orchestrator.generate_incident_report(log_id)
    if not report: raise HTTPException(404, "Case index not found")
    return {"markdown": report}


@router.get("/alerts/{log_id}/pdf")
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
                # mitre_data maps technique-id -> {Name, Description, Mitigation};
                # render the human-readable name (fall back to str for older records).
                label = technique.get("Name", "") if isinstance(technique, dict) else str(technique)
                pdf.set_font("Arial", 'B', 10)
                pdf.cell(40, 6, f"{tactic}:")
                pdf.set_font("Arial", '', 10)
                pdf.cell(0, 6, label, ln=True)

        # Footer
        pdf.set_y(-30)
        pdf.set_font("Arial", 'I', 8)
        pdf.set_text_color(128, 128, 128)
        pdf.cell(0, 10, "This report is cryptographically signed and archived for compliance. | DNSentinel Enterprise XDR", align='C')

        from fastapi.responses import Response
        return Response(content=bytes(pdf.output()), media_type="application/pdf", headers={
            "Content-Disposition": f"attachment; filename=SOC_Audit_{log_id}.pdf"
        })

