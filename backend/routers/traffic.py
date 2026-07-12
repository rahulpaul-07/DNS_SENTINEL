"""Recent-traffic feed and aggregate SOC statistics."""
from fastapi import APIRouter, Response

from database import SessionLocal, DNSAuditLog

router = APIRouter()


@router.get("/traffic")
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


@router.get("/stats")
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

