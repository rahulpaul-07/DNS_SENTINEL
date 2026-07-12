"""CSV and PDF forensic export endpoints."""
import csv
import io
from datetime import datetime

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from fpdf import FPDF

from database import SessionLocal, DNSAuditLog
from state import VALID_RISK_LEVELS

router = APIRouter()


@router.get("/export")
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


@router.get("/export/pdf")
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


@router.get("/export/alerts.csv")
async def export_alerts_csv(risk_level: str = None):
    """Stream a downloadable CSV of the audit ledger.

    Unlike /export (which returns JSON-wrapped text), this returns a real
    text/csv attachment browsers download directly. Optionally filter to a
    single risk_level (Low|Medium|High|Critical).
    """
    level = None
    if risk_level:
        level = risk_level.strip().capitalize()
        if level not in VALID_RISK_LEVELS:
            raise HTTPException(
                status_code=400,
                detail=f"invalid risk_level '{risk_level}'; expected one of "
                f"{sorted(VALID_RISK_LEVELS)}",
            )

    def row_iter():
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            ["timestamp", "source_ip", "query", "qtype",
             "risk_score", "risk_level", "prediction", "mitre_ids"]
        )
        yield buffer.getvalue()
        buffer.seek(0); buffer.truncate(0)

        with SessionLocal() as db:
            q = db.query(DNSAuditLog)
            if level:
                q = q.filter(DNSAuditLog.risk_level == level)
            for log in q.order_by(DNSAuditLog.id.desc()).all():
                writer.writerow([
                    log.timestamp.isoformat() if log.timestamp else "",
                    log.source_ip,
                    log.query,
                    log.qtype,
                    log.risk_score,
                    log.risk_level,
                    log.prediction,
                    ", ".join(log.mitre_data.keys()) if log.mitre_data else "",
                ])
                yield buffer.getvalue()
                buffer.seek(0); buffer.truncate(0)

    filename = f"dnsentinel_alerts_{datetime.now():%Y%m%d_%H%M%S}.csv"
    return StreamingResponse(
        row_iter(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

