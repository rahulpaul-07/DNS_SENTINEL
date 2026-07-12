"""Liveness, version, SSE stream and WebSocket endpoints."""
import asyncio
import json
import logging

from fastapi import APIRouter, Request, WebSocket
from fastapi.responses import JSONResponse, StreamingResponse

from config import settings
from database import SessionLocal, DNSAuditLog
from state import manager

logger = logging.getLogger("DNSentinel")
router = APIRouter()


@router.get("/")
async def root():
    return {"status": "DNSentinel Backend Online", "docs": "/docs"}


@router.get("/health")
async def health():
    """Lightweight liveness probe for load balancers and uptime checks."""
    db_ok = True
    try:
        with SessionLocal() as db:
            db.query(DNSAuditLog).limit(1).all()
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(f"Health check DB probe failed: {exc}")
        db_ok = False
    status_code = 200 if db_ok else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "healthy" if db_ok else "degraded",
            "database": "up" if db_ok else "down",
            "version": settings.VERSION,
        },
    )


@router.get("/version")
async def version():
    """Report the running application version and name."""
    return {"app": settings.APP_NAME, "version": settings.VERSION}


@router.get("/stream")
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


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except Exception:
        manager.disconnect(websocket)

