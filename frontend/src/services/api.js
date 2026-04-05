const API_BASE = "/api";
const WS_BASE = `ws://${window.location.host}/ws`;

export const fetchAlerts = async () => {
    const response = await fetch(`${API_BASE}/alerts`);
    return response.json();
};

export const fetchStats = async () => {
    const response = await fetch(`${API_BASE}/stats`);
    return response.json();
};

export const uploadDataset = async (file) => {
    const formData = new FormData();
    formData.append("file", file);
    
    const response = await fetch(`${API_BASE}/upload`, {
        method: "POST",
        body: formData,
    });
    return response.json();
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

export const connectWebSocket = (onMessage) => {
    let socket = new WebSocket(WS_BASE);
    
    socket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        onMessage(data);
    };
    
    socket.onclose = () => {
        console.log("WebSocket Disconnected. Reconnecting in 3s...");
        setTimeout(() => connectWebSocket(onMessage), 3000);
    };
    
    return socket;
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
