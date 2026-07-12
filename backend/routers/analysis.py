"""Single-query analysis endpoint (thin wrapper over services.analysis)."""
from fastapi import APIRouter

from schemas import DNSLog
from services.analysis import analyze_dns

router = APIRouter()


@router.post("/analyze")
async def analyze_dns_endpoint(log: DNSLog, skip_intel: bool = False, skip_broadcast: bool = False):
    return await analyze_dns(log, skip_intel, skip_broadcast)

