"""Centralised runtime configuration for the DNSentinel backend.

All tunables are read from environment variables (optionally loaded from a
local .env file) so the same image runs unchanged across dev, CI and the
Render deployment. See .env.example for the full list.
"""
import os

try:
    # Optional: load a local .env during development. Never required in prod.
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover - dotenv is optional
    pass


def _read_version() -> str:
    """Read the project VERSION file (repo root), falling back to 0.0.0."""
    here = os.path.dirname(__file__)
    for candidate in (
        os.path.join(here, "..", "VERSION"),
        os.path.join(here, "VERSION"),
    ):
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                value = fh.read().strip()
                if value:
                    return value
        except OSError:
            continue
    return "0.0.0"


def _split_csv(value: str):
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings:
    """Process-wide settings, resolved once at import time."""

    APP_NAME = "DNSentinel"
    VERSION = _read_version()

    # Comma-separated list of allowed CORS origins. "*" allows all (dev default).
    CORS_ORIGINS = _split_csv(os.getenv("CORS_ORIGINS", "*")) or ["*"]

    # Threat-intel providers (optional; features degrade gracefully if unset).
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

    DEBUG = os.getenv("DEBUG", "False").lower() in {"1", "true", "yes"}
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

    # Upper bound on an accepted DNS query name (RFC 1035 caps FQDNs at 253).
    MAX_QUERY_LENGTH = int(os.getenv("MAX_QUERY_LENGTH", "253"))


settings = Settings()
