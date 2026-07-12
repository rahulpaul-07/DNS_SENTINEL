"""Shared in-process runtime state for the DNSentinel backend.

Extracted from the former monolithic main.py so routers and services can share
the same live objects (telemetry deques, per-IP history, the SSE/WebSocket
connection manager) without circular imports. All objects here are mutated in
place — never rebound — so importing them by name is safe across modules.
"""
import asyncio
import time
from collections import deque

from fastapi import WebSocket

# Rolling operational buffers (bounded so memory stays flat under load).
traffic_history: deque = deque(maxlen=200)
alerts: deque = deque(maxlen=100)
ip_query_history: dict = {}
alert_groups: dict = {}

# Risk tiers accepted by filtering endpoints (mirrors RiskEngine tiers).
VALID_RISK_LEVELS = {"Low", "Medium", "High", "Critical"}


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
            except Exception:
                pass
        # 2. SSE Broadcast
        for queue in self.sse_queues:
            await queue.put(message)


manager = ConnectionManager()


def calculate_frequency_for_ip(ip):
    current_time = time.time()
    if ip not in ip_query_history:
        ip_query_history[ip] = []
    ip_query_history[ip] = [t for t in ip_query_history[ip] if current_time - t < 60]
    return len(ip_query_history[ip])
