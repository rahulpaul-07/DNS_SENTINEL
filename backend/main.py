"""DNSentinel backend — application assembly.

This module is intentionally thin: it wires configuration, middleware, the
lifespan background task, the global exception handler, and mounts the feature
routers. All business logic lives in `services/` and the endpoint groups in
`routers/`. The ASGI entrypoint is still `main:app`, so existing deploy
commands (`uvicorn main:app ...`) are unchanged.
"""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings
from database import init_db

# Create tables BEFORE importing anything that depends on them (SOAR actions).
init_db()

from services.analysis import soar_maintenance  # noqa: E402
from routers import (  # noqa: E402
    alerts,
    analysis,
    core,
    export,
    ingest,
    soar,
    traffic,
)

logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL, logging.INFO))
logger = logging.getLogger("DNSentinel")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Background SOAR rule-expiry sweeper. (Live packet capture is intentionally
    # disabled here for deployment stability; see services.capture.)
    maintenance_task = asyncio.create_task(soar_maintenance())
    yield
    maintenance_task.cancel()
    logger.info("DNSentinel background tasks: SHUTDOWN")


app = FastAPI(
    title="DNSentinel: Enterprise DNS Exfiltration Detection",
    version=settings.VERSION,
    lifespan=lifespan,
)

# Robust CORS for both HTTP and WebSockets.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount feature routers.
for _module in (core, analysis, ingest, alerts, soar, traffic, export):
    app.include_router(_module.router)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"CRITICAL_SERVER_FAULT: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"message": "Internal SOAR Orchestration Fault", "details": str(exc)},
    )
