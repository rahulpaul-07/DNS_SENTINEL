"""Pydantic request/response schemas for the DNSentinel API."""
from pydantic import BaseModel

try:
    from pydantic import field_validator  # pydantic v2
    _PYDANTIC_V2 = True
except ImportError:  # pragma: no cover - pydantic v1 fallback
    from pydantic import validator as field_validator
    _PYDANTIC_V2 = False

from config import settings


class DNSLog(BaseModel):
    timestamp: float = None
    query: str
    source_ip: str = "0.0.0.0"
    qtype: str = "A"

    @field_validator("query")
    @classmethod
    def _validate_query(cls, v):
        v = (v or "").strip()
        if not v:
            raise ValueError("query must not be empty")
        if len(v) > settings.MAX_QUERY_LENGTH:
            raise ValueError(
                f"query exceeds max length of {settings.MAX_QUERY_LENGTH} characters"
            )
        return v.lower()

    @field_validator("qtype")
    @classmethod
    def _validate_qtype(cls, v):
        return (v or "A").strip().upper()[:10]
