// In production (Vercel), VITE_API_URL points to the Render backend (e.g. https://dnsentinel.onrender.com)
// In development, we use '/api' which is proxied by vite.config.js to http://127.0.0.1:8001
const PROD_API = import.meta.env.VITE_API_URL || '';
const API_BASE = PROD_API ? `${PROD_API}` : '/api';

// WebSocket: wss:// in production, ws:// in development
const WS_BASE = PROD_API
  ? `${PROD_API.replace(/^http/, 'ws')}/ws`
  : `ws://${window.location.host}/ws`;

const SSE_BASE = `${API_BASE}/stream`;

export const fetchAlerts = async ({ riskLevel = null, limit = 50, offset = 0 } = {}) => {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (riskLevel) params.set("risk_level", riskLevel);
    const response = await fetch(`${API_BASE}/alerts?${params.toString()}`);
    return response.json();
};

// Returns a direct download URL for the streaming CSV export (optionally filtered).
export const getExportCsvUrl = (riskLevel = null) => {
    const params = new URLSearchParams();
    if (riskLevel) params.set("risk_level", riskLevel);
    const qs = params.toString();
    return `${API_BASE}/export/alerts.csv${qs ? `?${qs}` : ""}`;
};

export const fetchStats = async () => {
    const response = await fetch(`${API_BASE}/stats`);
    return response.json();
};

export const uploadDataset = async (file) => {
    const formData = new FormData();
    formData.append("file", file);
    
    try {
        const response = await fetch(`${API_BASE}/upload`, {
            method: "POST",
            body: formData,
        });
        
        if (!response.ok) {
            const text = await response.text();
            throw new Error(`Server Error (${response.status}): ${text || "Unknown error"}`);
        }
        
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
            return await response.json();
        } else {
            return { status: "success", message: "Upload accepted. Processing in background." };
        }
    } catch (err) {
        console.error("Upload Service Error:", err);
        throw err;
    }
}

export const downloadLogs = async () => {
    const response = await fetch(`${API_BASE}/export`);
    const data = await response.json();
    return data.csv;
}

export const trainModel = async (file) => {
    const formData = new FormData();
    formData.append("file", file);
    
    const response = await fetch(`${API_BASE}/train`, {
        method: "POST",
        body: formData,
    });
    
    if(!response.ok) {
        const err = await response.json();
        throw new Error(err.detail);
    }
    
    return response.json();
}

export const connectWebSocket = (onMessage, onOpen, onClose) => {
    let socket = new WebSocket(WS_BASE);
    
    socket.onopen = () => {
        if (onOpen) onOpen();
    };

    socket.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            onMessage(data);
        } catch (e) {
            console.error("WS Parse Error:", e);
        }
    };
    
    socket.onclose = () => {
        if (onClose) onClose();
        console.log("WebSocket Disconnected. Reconnecting in 3s...");
        setTimeout(() => connectWebSocket(onMessage, onOpen, onClose), 3000);
    };
    
    return socket;
};

/**
 * Connects to the Server-Sent Events (SSE) stream.
 * SSE is much more stable than WebSockets for high-frequency logs in dev environments.
 */
export const connectSSE = (onMessage, onOpen, onError) => {
    const eventSource = new EventSource(SSE_BASE);

    eventSource.onopen = () => {
        console.log("🚀 SSE Connected");
        if (onOpen) onOpen();
    };

    eventSource.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            onMessage(data);
        } catch (e) {
            console.error("SSE Parse Error:", e);
        }
    };

    eventSource.onerror = (err) => {
        console.error("SSE Connection Error:", err);
        if (onError) onError(err);
        // Browser handles auto-reconnection for SSE, so no manual timeout needed here
    };

    return eventSource;
};

export const blockIP = async (logId) => {
    const response = await fetch(`${API_BASE}/alerts/${logId}/block`, { method: "POST" });
    return response.json();
}

export const markBenign = async (logId) => {
    const response = await fetch(`${API_BASE}/alerts/${logId}/feedback`, { method: "POST" });
    return response.json();
}

export const fetchIncidentReport = async (logId) => {
    const response = await fetch(`${API_BASE}/alerts/${logId}/report`);
    return response.json();
}
