import { calculateFallbackScore, extractFeatures } from '../background/heuristics.js';

function parseExplanation(rawText, score = 0) {
    if (!rawText || rawText === "[Local Engine] Analyzing structural features...") {
        return { friendly: "Analyzing structural and security patterns...", technical: "", pie: "" };
    }

    if (score < 50) {
        return {
            friendly: "This website behaves normally. Our machine learning models evaluated its name and found no malicious patterns.",
            technical: rawText,
            pie: ""
        };
    }

    const parts = rawText.split('|').map(p => p.trim());
    let threatText = "";
    let shapText = "";
    let pieText = "";

    parts.forEach(part => {
        if (part.includes("PIE Score")) {
            pieText = part;
        } else if (part.includes("[XAI: SHAP]")) {
            shapText = part;
        } else {
            threatText = threatText ? (threatText + " " + part) : part;
        }
    });

    let friendly = "";
    if (threatText.includes("Standard benign DNS") || threatText.includes("Normal traffic structures")) {
        friendly = "This website behaves normally. Our machine learning models evaluated its name and found no malicious patterns.";
    } else {
        const bulletPoints = [];
        if (threatText.includes("Isolation Forest flagged")) {
            bulletPoints.push("Our AI detected unusual patterns that differ from standard, trusted web destinations.");
        }
        if (threatText.includes("human-readable n-grams") || threatText.includes("DGA generated")) {
            bulletPoints.push("The domain name looks randomized and doesn't match standard language patterns, which is typical for automated command systems.");
        }
        if (threatText.includes("entropy") || threatText.includes("tunneling")) {
            bulletPoints.push("The website name contains random, high-entropy character sequences resembling encoded data exfiltration.");
        }
        if (threatText.includes("long DNS label")) {
            bulletPoints.push("The web address contains excessively long parts, which is a known method for sneaking data out.");
        }

        if (bulletPoints.length > 0) {
            friendly = bulletPoints.join(" ");
        } else {
            friendly = "Our machine learning model detected suspicious structural deviations that may represent an active threat.";
        }
    }

    return {
        friendly,
        technical: threatText + (shapText ? " | " + shapText : ""),
        pie: pieText
    };
}

// Utility function to create elements with classes
function create(tag, classes = '', innerHTML = '') {
    const el = document.createElement(tag);
    if (classes) el.className = classes;
    if (innerHTML) el.innerHTML = innerHTML;
    return el;
}

let events = [];
let stats = { total: 0, blocked: 0, alerts: 0, maxScore: 0 };
let selectedEvent = null;
let activeTabDomain = null;
let activeTabEvent = null;
let isActiveTabSystem = false;
let activeTabUrl = "";
let showSettings = false;
let savedBackendUrl = "http://127.0.0.1:8001";
let savedGroqKey = "";

// Load settings from Chrome storage
chrome.storage.local.get(["BACKEND_API_URL", "GROQ_API_KEY"], (result) => {
    if (result.BACKEND_API_URL) savedBackendUrl = result.BACKEND_API_URL;
    if (result.GROQ_API_KEY) savedGroqKey = result.GROQ_API_KEY;
});

function determineTier(score) {
    if (score > 90) return "CRITICAL";
    if (score > 80) return "BLOCK";
    if (score > 60) return "ALERT";
    return "MONITOR";
}

function triggerLocalCalculation(domain, url, tabId) {
    const features = extractFeatures(domain);
    const scoreData = calculateFallbackScore(features, domain);

    activeTabEvent = {
        id: "temp_" + Date.now(),
        domain,
        url,
        tabId,
        timestamp: Date.now(),
        features,
        ml_score: scoreData.ml_score || 0.5,
        isolation_score: 1,
        final_score: scoreData.final_score,
        shap_reason: "[Local Engine] Calculating initial scores...",
        tier: determineTier(scoreData.final_score),
        detailsType: "main_frame"
    };
    render();
}

function detectActiveTab() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs && tabs[0] && tabs[0].url) {
            activeTabUrl = tabs[0].url;
            try {
                const url = new URL(activeTabUrl);
                if (url.protocol.startsWith('http')) {
                    activeTabDomain = url.hostname;
                    isActiveTabSystem = false;

                    const existing = events.find(ev =>
                        ev.domain === activeTabDomain ||
                        activeTabDomain.endsWith('.' + ev.domain) ||
                        ev.domain.endsWith('.' + activeTabDomain)
                    );

                    if (existing) {
                        activeTabEvent = existing;
                        render();
                    } else {
                        chrome.runtime.sendMessage({
                            type: "ANALYZE_DOMAIN",
                            domain: activeTabDomain,
                            url: activeTabUrl,
                            tabId: tabs[0].id
                        });
                        triggerLocalCalculation(activeTabDomain, activeTabUrl, tabs[0].id);
                    }
                } else {
                    activeTabDomain = url.hostname || url.protocol;
                    isActiveTabSystem = true;
                    activeTabEvent = null;
                    render();
                }
            } catch (e) {
                console.error("Error parsing tab URL:", e);
                isActiveTabSystem = true;
                render();
            }
        }
    });
}

// Load events from IndexedDB
function loadEvents() {
    const request = indexedDB.open("DNSentinelDB", 1);
    request.onsuccess = (e) => {
        const db = e.target.result;
        if(db.objectStoreNames.contains("dns_events")) {
            const tx = db.transaction("dns_events", "readonly");
            const store = tx.objectStore("dns_events");
            const getReq = store.getAll();
            getReq.onsuccess = () => {
                const all = getReq.result || [];
                events = all.sort((a,b) => b.timestamp - a.timestamp).slice(0, 20);

                let blocked = 0, alerts = 0, max = 0;
                all.forEach(ev => {
                    if (['BLOCK', 'CRITICAL', 'HIGH'].includes(ev.tier)) blocked++;
                    if (['ALERT', 'BLOCK', 'CRITICAL', 'HIGH', 'MEDIUM'].includes(ev.tier)) alerts++;
                    if (ev.final_score > max) max = ev.final_score;
                });
                stats = { total: all.length, blocked, alerts, maxScore: max };

                detectActiveTab();
            };
        }
    };
}

// Listen for new DNS events
chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "DNS_EVENT") {
        const index = events.findIndex(ev => ev.id === msg.payload.id);
        if (index !== -1) {
            const oldEvent = events[index];
            events[index] = msg.payload;

            if (['BLOCK', 'CRITICAL', 'HIGH'].includes(oldEvent.tier)) stats.blocked--;
            if (['ALERT', 'BLOCK', 'CRITICAL', 'HIGH', 'MEDIUM'].includes(oldEvent.tier)) stats.alerts--;

            if (['BLOCK', 'CRITICAL', 'HIGH'].includes(msg.payload.tier)) stats.blocked++;
            if (['ALERT', 'BLOCK', 'CRITICAL', 'HIGH', 'MEDIUM'].includes(msg.payload.tier)) stats.alerts++;
            if (msg.payload.final_score > stats.maxScore) stats.maxScore = msg.payload.final_score;

            if (selectedEvent && selectedEvent.id === msg.payload.id) {
                selectedEvent = msg.payload;
            }
        } else {
            events.unshift(msg.payload);
            if (events.length > 20) events.pop();
            stats.total++;
            if (['BLOCK', 'CRITICAL', 'HIGH'].includes(msg.payload.tier)) stats.blocked++;
            if (['ALERT', 'BLOCK', 'CRITICAL', 'HIGH', 'MEDIUM'].includes(msg.payload.tier)) stats.alerts++;
            if (msg.payload.final_score > stats.maxScore) stats.maxScore = msg.payload.final_score;
        }

        if (activeTabDomain && (msg.payload.domain === activeTabDomain || activeTabDomain.endsWith('.' + msg.payload.domain) || msg.payload.domain.endsWith('.' + activeTabDomain))) {
            activeTabEvent = msg.payload;
        }

        render();
    }
});

function getTierColor(tier) {
    switch(tier) {
        case 'CRITICAL':
        case 'HIGH':
            return 'rgb(239, 68, 68)';
        case 'BLOCK':
        case 'MEDIUM':
            return 'rgb(249, 115, 22)';
        case 'ALERT':
            return 'rgb(234, 179, 8)';
        default:
            return 'rgb(16, 185, 129)';
    }
}

function getTierBgColor(tier) {
    switch(tier) {
        case 'CRITICAL':
        case 'HIGH':
            return '#7f1d1d';
        case 'BLOCK':
        case 'MEDIUM':
            return '#7c2d12';
        case 'ALERT':
            return '#713f12';
        default:
            return '#064e3b';
    }
}

function clearData() {
    const request = indexedDB.open("DNSentinelDB", 1);
    request.onsuccess = (e) => {
        const db = e.target.result;
        if(db.objectStoreNames.contains("dns_events")) {
            const tx = db.transaction("dns_events", "readwrite");
            tx.objectStore("dns_events").clear();
            tx.oncomplete = () => {
                events = [];
                stats = { total: 0, blocked: 0, alerts: 0, maxScore: 0 };
                selectedEvent = null;
                render();
            };
        }
    };
}

function render() {
    const root = document.getElementById('root');
    root.innerHTML = '';

    if (showSettings) {
        // Settings view
        const settingsDiv = document.createElement('div');
        settingsDiv.style.cssText = `position:absolute;inset:0;background:rgba(9,15,30,0.97);backdrop-filter:blur(20px);z-index:20;display:flex;flex-direction:column;height:100%;border-radius:8px;overflow:hidden`;

        // Header
        const header = document.createElement('div');
        header.style.cssText = `padding:1rem;border-bottom:1px solid rgba(255,255,255,0.05);display:flex;justify-content:space-between;align-items:center;background:rgba(15,23,42,0.8);backdrop-filter:blur(12px);z-index:10`;
        header.innerHTML = `
            <div style="display:flex;align-items:center;gap:0.75rem;overflow:hidden;flex:1">
                <button id="closeSettings" style="color:#94a3b8;background:rgba(30,41,59,0.5);border:1px solid rgba(255,255,255,0.05);width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:all 0.2s">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
                </button>
                <h3 style="font-weight:bold;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:white;font-size:16px;margin:0;letter-spacing:0.02em">Extension Settings</h3>
            </div>
        `;

        // Content
        const content = document.createElement('div');
        content.style.cssText = `padding:1.25rem;flex:1;overflow-y:auto;font-size:0.875rem;display:flex;flex-direction:column;gap:1.5rem`;

        content.innerHTML = `
            <div style="display:flex;flex-direction:column;gap:0.5rem">
                <label style="color:#cbd5e1;font-weight:600;font-size:13px">Backend Server URL</label>
                <input id="backendUrlInput" type="text" value="${savedBackendUrl}" placeholder="http://127.0.0.1:8001" style="background:rgba(30,41,59,0.5);border:1px solid rgba(255,255,255,0.1);border-radius:0.5rem;padding:0.625rem 0.875rem;color:white;font-family:monospace;font-size:13px;outline:none;transition:border-color 0.2s;box-sizing:border-box;width:100%" />
                <p style="margin:0;font-size:10.5px;color:#64748b;line-height:1.4">Specify the URL of the FastAPI machine learning inference engine. Can be hosted locally or on a cloud server.</p>
            </div>

            <div style="display:flex;flex-direction:column;gap:0.5rem">
                <label style="color:#cbd5e1;font-weight:600;font-size:13px">Groq API Key</label>
                <input id="groqKeyInput" type="password" value="${savedGroqKey}" placeholder="gsk_..." style="background:rgba(30,41,59,0.5);border:1px solid rgba(255,255,255,0.1);border-radius:0.5rem;padding:0.625rem 0.875rem;color:white;font-family:monospace;font-size:13px;outline:none;transition:border-color 0.2s;box-sizing:border-box;width:100%" />
                <p style="margin:0;font-size:10.5px;color:#64748b;line-height:1.4">Your personal Groq API Key. Used as a direct LLM fallback for XAI (Explainable AI) analysis if the backend server is temporarily unreachable.</p>
            </div>
        `;

        // Focus ring effect for inputs
        const inputs = content.querySelectorAll('input');
        inputs.forEach(input => {
            input.onfocus = () => input.style.borderColor = '#22d3ee';
            input.onblur = () => input.style.borderColor = 'rgba(255,255,255,0.1)';
        });

        // Footer with save button
        const footer = document.createElement('div');
        footer.style.cssText = `border-top:1px solid rgba(255,255,255,0.05);background:rgba(15,23,42,0.9);padding:1rem;display:flex;gap:0.75rem;z-index:10`;

        const saveBtn = document.createElement('button');
        saveBtn.style.cssText = `flex:1;background:#0284c7;color:white;font-weight:bold;padding:0.625rem 1rem;border-radius:0.5rem;border:none;cursor:pointer;font-size:14px;transition:all 0.2s;box-shadow:0 0 10px rgba(2,132,199,0.2)`;
        saveBtn.textContent = 'Save Settings';
        saveBtn.onmouseover = () => {
            saveBtn.style.background = '#0369a1';
            saveBtn.style.boxShadow = '0 0 15px rgba(3,105,161,0.4)';
            saveBtn.style.transform = 'scale(1.02)';
        };
        saveBtn.onmouseout = () => {
            saveBtn.style.background = '#0284c7';
            saveBtn.style.boxShadow = '0 0 10px rgba(2,132,199,0.2)';
            saveBtn.style.transform = 'scale(1)';
        };

        saveBtn.onclick = () => {
            const backendUrlVal = content.querySelector('#backendUrlInput').value.trim();
            const groqKeyVal = content.querySelector('#groqKeyInput').value.trim();

            chrome.storage.local.set({
                BACKEND_API_URL: backendUrlVal,
                GROQ_API_KEY: groqKeyVal
            }, () => {
                savedBackendUrl = backendUrlVal;
                savedGroqKey = groqKeyVal;

                const toast = document.createElement('div');
                toast.style.cssText = `position:fixed;bottom:20px;left:20px;background:#10b981;color:white;padding:0.875rem 1.25rem;border-radius:8px;font-size:13px;font-weight:bold;z-index:1000;box-shadow:0 10px 25px rgba(0,0,0,0.5);border:1px solid rgba(255,255,255,0.1)`;
                toast.textContent = `Settings saved successfully`;
                document.body.appendChild(toast);
                setTimeout(() => toast.remove(), 2000);

                showSettings = false;
                render();
            });
        };

        footer.appendChild(saveBtn);
        settingsDiv.appendChild(header);
        settingsDiv.appendChild(content);
        settingsDiv.appendChild(footer);

        header.querySelector('#closeSettings').onclick = () => {
            showSettings = false;
            render();
        };

        root.appendChild(settingsDiv);
    } else if (selectedEvent) {
        // Detail view with inline styles
        const detail = document.createElement('div');
        detail.style.cssText = `position:absolute;inset:0;background:rgba(9,15,30,0.97);backdrop-filter:blur(20px);z-index:20;display:flex;flex-direction:column;height:100%;border-radius:8px;overflow:hidden`;

        // Header
        const header = document.createElement('div');
        header.style.cssText = `padding:1rem;border-bottom:1px solid rgba(255,255,255,0.05);display:flex;justify-content:space-between;align-items:center;background:rgba(15,23,42,0.8);backdrop-filter:blur(12px);z-index:10`;
        header.innerHTML = `
            <div style="display:flex;align-items:center;gap:0.75rem;overflow:hidden;flex:1">
                <button id="closeDetail" style="color:#94a3b8;background:rgba(30,41,59,0.5);border:1px solid rgba(255,255,255,0.05);width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:all 0.2s">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
                </button>
                <h3 style="font-weight:bold;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:white;font-size:16px;margin:0;letter-spacing:0.02em" title="${selectedEvent.domain}">${selectedEvent.domain}</h3>
            </div>
        `;

        // Content
        const content = document.createElement('div');
        content.style.cssText = `padding:1.25rem;flex:1;overflow-y:auto;font-size:0.875rem;display:flex;flex-direction:column;gap:1.25rem`;

        const tierColor = (selectedEvent.tier === 'CRITICAL' || selectedEvent.tier === 'HIGH') ? '#ef4444' :
                          (selectedEvent.tier === 'BLOCK' || selectedEvent.tier === 'MEDIUM') ? '#f97316' :
                          selectedEvent.tier === 'ALERT' ? '#eab308' : '#10b981';

        // Risk Score
        const scoreBox = document.createElement('div');
        scoreBox.style.cssText = `display:flex;flex-direction:column;gap:0.5rem;background:linear-gradient(135deg, rgba(30,41,59,0.3) 0%, rgba(15,23,42,0.5) 100%);padding:1.25rem;border-radius:0.75rem;border:1px solid rgba(255,255,255,0.05);border-left:4px solid ${tierColor};position:relative;overflow:hidden;box-shadow:0 10px 20px rgba(0,0,0,0.3);flex-shrink:0`;

        const glowColor = (selectedEvent.tier === 'CRITICAL' || selectedEvent.tier === 'HIGH') ? 'rgba(239,68,68,0.06)' :
                          (selectedEvent.tier === 'BLOCK' || selectedEvent.tier === 'MEDIUM') ? 'rgba(249,115,22,0.04)' :
                          'rgba(34,211,238,0.03)';

        scoreBox.innerHTML = `
            <div style="position:absolute;inset:0;background:${glowColor};pointer-events:none;z-index:0"></div>
            <div style="display:flex;justify-content:space-between;align-items:center;position:relative;z-index:1">
                <span style="color:#cbd5e1;font-weight:600;font-size:13px">Threat Level (Risk Score)</span>
                <span style="font-family:monospace;font-size:1.75rem;font-weight:900;color:${tierColor};text-shadow:0 0 10px ${tierColor}55">${(selectedEvent.final_score || 0).toFixed(2)}</span>
            </div>
            <p style="margin:0;font-size:11px;color:#64748b;line-height:1.4;position:relative;z-index:1">Measures how suspicious the website itself is based on machine learning structural analysis.</p>
        `;
        content.appendChild(scoreBox);

        // Risk Tier Row
        const tierBox = document.createElement('div');
        tierBox.style.cssText = `display:flex;justify-content:space-between;align-items:center;padding:0.75rem 1rem;background:linear-gradient(135deg, rgba(30,41,59,0.2) 0%, rgba(15,23,42,0.3) 100%);border-radius:0.5rem;border:1px solid rgba(255,255,255,0.03);flex-shrink:0`;
        tierBox.innerHTML = `
            <span style="color:#cbd5e1;font-weight:600;font-size:13px">Risk Severity</span>
            <span style="padding:0.25rem 0.75rem;border-radius:0.375rem;font-size:10px;font-weight:900;border:1px solid ${tierColor}55;background:${tierColor}1a;color:${tierColor};box-shadow:0 0 10px ${tierColor}11;letter-spacing:0.05em">${selectedEvent.tier}</span>
        `;
        content.appendChild(tierBox);

        // AI Breakdown
        const breakdown = document.createElement('div');
        breakdown.style.cssText = `background:linear-gradient(135deg, rgba(30,41,59,0.3) 0%, rgba(15,23,42,0.5) 100%);padding:1.25rem;border-radius:0.75rem;border:1px solid rgba(255,255,255,0.05);display:flex;flex-direction:column;gap:1.25rem;box-shadow:0 10px 20px rgba(0,0,0,0.3);flex-shrink:0`;
        breakdown.innerHTML = `
            <div style="font-size:11px;font-weight:bold;color:#475569;text-transform:uppercase;letter-spacing:0.08em;border-bottom:1px solid rgba(255,255,255,0.03);padding-bottom:0.5rem">AI Risk Indicators</div>

            <div style="display:flex;flex-direction:column;gap:0.375rem">
                <div style="display:flex;justify-content:space-between;align-items:center;font-size:12px">
                    <span style="color:#e2e8f0;font-weight:600">Name Randomness (Entropy)</span>
                    <div style="display:flex;align-items:center;gap:0.5rem">
                        <div style="width:80px;height:6px;background:#1e293b;border-radius:9999px;overflow:hidden">
                            <div style="height:100%;background:#06b6d4;width:${Math.min((selectedEvent.features?.entropy || 0) * 20, 100)}%;box-shadow:0 0 8px #06b6d4"></div>
                        </div>
                        <span style="color:#22d3ee;font-family:monospace;font-size:10px;font-weight:bold">${(selectedEvent.features?.entropy || 0).toFixed(2)}</span>
                    </div>
                </div>
                <p style="margin:0;font-size:10.5px;color:#64748b;line-height:1.4">Checks how chaotic the address letters are. High randomness is a major indicator of hacker-controlled networks.</p>
            </div>

            <div style="display:flex;flex-direction:column;gap:0.375rem">
                <div style="display:flex;justify-content:space-between;align-items:center;font-size:12px">
                    <span style="color:#e2e8f0;font-weight:600">Number Ratio (Digits)</span>
                    <div style="display:flex;align-items:center;gap:0.5rem">
                        <div style="width:80px;height:6px;background:#1e293b;border-radius:9999px;overflow:hidden">
                            <div style="height:100%;background:#818cf8;width:${(selectedEvent.features?.digit_ratio || 0) * 100}%;box-shadow:0 0 8px #818cf8"></div>
                        </div>
                        <span style="color:#a78bfa;font-family:monospace;font-size:10px;font-weight:bold">${((selectedEvent.features?.digit_ratio || 0) * 100).toFixed(0)}%</span>
                    </div>
                </div>
                <p style="margin:0;font-size:10.5px;color:#64748b;line-height:1.4">Checks what percentage of characters are numbers. Legitimate sites rarely use number-packed names.</p>
            </div>
        `;
        content.appendChild(breakdown);

        // AI Reasoning - Website Oriented
        const parsed = parseExplanation(selectedEvent.shap_reason, selectedEvent.final_score);
        const reasoning = document.createElement('div');
        reasoning.style.cssText = `background:linear-gradient(135deg, rgba(30,41,59,0.3) 0%, rgba(15,23,42,0.5) 100%);padding:1.25rem;border-radius:0.75rem;border:1px solid rgba(255,255,255,0.05);display:flex;flex-direction:column;gap:0.75rem;box-shadow:0 10px 20px rgba(0,0,0,0.3);flex-shrink:0`;

        let reasoningHTML = `
            <div>
                <div style="font-size:11px;font-weight:bold;color:#475569;text-transform:uppercase;letter-spacing:0.08em;border-bottom:1px solid rgba(255,255,255,0.03);padding-bottom:0.5rem;margin-bottom:0.5rem">AI Assessment</div>
                <p style="font-size:12.5px;color:#f1f5f9;line-height:1.55;margin:0;font-weight:500">${parsed.friendly}</p>
            </div>
        `;

        if (parsed.pie) {
            reasoningHTML += `
                <div style="padding-top:0.75rem;border-top:1px solid rgba(255,255,255,0.03);display:flex;flex-direction:column;gap:0.25rem">
                    <div style="display:flex;justify-content:space-between;align-items:center;font-size:12.5px">
                        <span style="color:#cbd5e1;font-weight:500">Response Urgency (PIE Score)</span>
                        <span style="font-family:monospace;color:#22d3ee;font-weight:bold;text-shadow:0 0 5px rgba(34,211,238,0.4)">${parsed.pie}</span>
                    </div>
                    <p style="margin:0;font-size:10px;color:#64748b;line-height:1.4">Determines operational action priority by weighting the website's threat score against the security value of this computer.</p>
                </div>
            `;
        }

        if (parsed.technical) {
            reasoningHTML += `
                <details style="padding-top:0.75rem;border-top:1px solid rgba(255,255,255,0.03)">
                    <summary style="font-size:10.5px;font-weight:bold;color:#475569;text-transform:uppercase;letter-spacing:0.05em;cursor:pointer;list-style:none;display:flex;justify-content:space-between;align-items:center">
                        Developer Logs (SHAP & ML) <span style="font-size:9px">▼</span>
                    </summary>
                    <p style="margin-top:0.5rem;font-size:10.5px;color:#94a3b8;font-family:monospace;line-height:1.4;background:rgba(2,6,23,0.5);padding:0.625rem;border-radius:0.375rem;border:1px solid rgba(255,255,255,0.03);word-break:break-all">${parsed.technical}</p>
                </details>
            `;
        }

        reasoning.innerHTML = reasoningHTML;
        content.appendChild(reasoning);

        // Footer with buttons
        const footer = document.createElement('div');
        footer.style.cssText = `border-top:1px solid rgba(255,255,255,0.05);background:rgba(15,23,42,0.9);padding:1rem;display:flex;gap:0.75rem;z-index:10`;

        const allowBtn = document.createElement('button');
        allowBtn.style.cssText = `flex:1;background:#059669;color:white;font-weight:bold;padding:0.625rem 1rem;border-radius:0.5rem;border:none;cursor:pointer;font-size:14px;transition:all 0.2s;box-shadow:0 0 10px rgba(5,150,105,0.2)`;
        allowBtn.textContent = 'Allow';
        allowBtn.onmouseover = () => {
            allowBtn.style.background = '#047857';
            allowBtn.style.boxShadow = '0 0 15px rgba(4,120,87,0.4)';
            allowBtn.style.transform = 'scale(1.02)';
        };
        allowBtn.onmouseout = () => {
            allowBtn.style.background = '#059669';
            allowBtn.style.boxShadow = '0 0 10px rgba(5,150,105,0.2)';
            allowBtn.style.transform = 'scale(1)';
        };
        allowBtn.onclick = () => {
            chrome.runtime.sendMessage({ type: "ALLOW_DOMAIN", domain: selectedEvent.domain }, (response) => {
                if (response && response.status === "allowed") {
                    const toast = document.createElement('div');
                    toast.style.cssText = `position:fixed;bottom:20px;left:20px;background:#10b981;color:white;padding:0.875rem 1.25rem;border-radius:8px;font-size:13px;font-weight:bold;z-index:1000;box-shadow:0 10px 25px rgba(0,0,0,0.5);border:1px solid rgba(255,255,255,0.1)`;
                    toast.textContent = `${selectedEvent.domain} allowed`;
                    document.body.appendChild(toast);
                    setTimeout(() => toast.remove(), 2000);
                }
                selectedEvent = null;
                render();
            });
        };

        const blockBtn = document.createElement('button');
        blockBtn.style.cssText = `flex:1;background:#dc2626;color:white;font-weight:bold;padding:0.625rem 1rem;border-radius:0.5rem;border:none;cursor:pointer;font-size:14px;transition:all 0.2s;box-shadow:0 0 10px rgba(220,38,38,0.2)`;
        blockBtn.textContent = 'Block';
        blockBtn.onmouseover = () => {
            blockBtn.style.background = '#b91c1c';
            blockBtn.style.boxShadow = '0 0 15px rgba(185,28,28,0.4)';
            blockBtn.style.transform = 'scale(1.02)';
        };
        blockBtn.onmouseout = () => {
            blockBtn.style.background = '#dc2626';
            blockBtn.style.boxShadow = '0 0 10px rgba(220,38,38,0.2)';
            blockBtn.style.transform = 'scale(1)';
        };
        blockBtn.onclick = () => {
            chrome.runtime.sendMessage({ type: "BLOCK_DOMAIN", domain: selectedEvent.domain }, (response) => {
                if (response && response.status === "blocked") {
                    const toast = document.createElement('div');
                    toast.style.cssText = `position:fixed;bottom:20px;left:20px;background:#dc2626;color:white;padding:0.875rem 1.25rem;border-radius:8px;font-size:13px;font-weight:bold;z-index:1000;box-shadow:0 10px 25px rgba(0,0,0,0.5);border:1px solid rgba(255,255,255,0.1)`;
                    toast.textContent = `${selectedEvent.domain} blocked`;
                    document.body.appendChild(toast);
                    setTimeout(() => toast.remove(), 2000);
                }
                selectedEvent = null;
                render();
            });
        };

        footer.appendChild(allowBtn);
        footer.appendChild(blockBtn);

        detail.appendChild(header);
        detail.appendChild(content);
        detail.appendChild(footer);

        header.querySelector('#closeDetail').onclick = () => {
            selectedEvent = null;
            render();
        };

        root.appendChild(detail);
    } else {
        // Main view
        const container = document.createElement('div');
        container.style.cssText = `display:flex;flex-direction:column;height:100%;background:#020617;color:white;overflow:hidden;position:relative`;

        // Glow effects
        const glow1 = document.createElement('div');
        glow1.style.cssText = `position:absolute;top:-50px;left:-50px;width:200px;height:200px;background:rgba(34,211,238,0.15);border-radius:50%;filter:blur(60px);pointer-events:none`;
        const glow2 = document.createElement('div');
        glow2.style.cssText = `position:absolute;bottom:-50px;right:-50px;width:256px;height:256px;background:rgba(99,102,241,0.08);border-radius:50%;filter:blur(60px);pointer-events:none`;

        // Header
        const header = document.createElement('div');
        header.style.cssText = `display:flex;justify-content:space-between;align-items:center;padding:1rem;background:rgba(15,23,42,0.6);backdrop-filter:blur(12px);border-bottom:1px solid rgba(255,255,255,0.05);z-index:10`;
        header.innerHTML = `
            <div style="display:flex;align-items:center;gap:0.625rem">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#22d3ee" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="filter:drop-shadow(0 0 5px rgba(34,211,238,0.5))"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                <span style="font-weight:bold;font-size:18px;letter-spacing:0.02em;background:linear-gradient(to right,#22d3ee,#6366f1);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text">DNSentinel</span>
                <span style="color:#22d3ee;font-size:9px;font-weight:900;background:rgba(22,78,99,0.6);padding:0.25rem 0.5rem;border-radius:0.25rem;border:1px solid rgba(34,211,238,0.3);letter-spacing:0.05em;text-transform:uppercase;box-shadow:0 0 8px rgba(34,211,238,0.2);animation:pulse 2s infinite">Live</span>
            </div>
            <div style="display:flex;gap:0.75rem">
                <button id="clearBtn" style="color:#64748b;background:transparent;border:none;cursor:pointer;font-size:16px;transition:color 0.2s;display:flex;align-items:center" title="Clear Data">
                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
                </button>
                <button id="settingsBtn" style="color:#64748b;background:transparent;border:none;cursor:pointer;font-size:16px;transition:color 0.2s;display:flex;align-items:center" title="Settings">
                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
                </button>
            </div>
        `;

        header.querySelector('#clearBtn').onclick = clearData;
        header.querySelector('#clearBtn').onmouseover = () => header.querySelector('#clearBtn').style.color = '#f87171';
        header.querySelector('#clearBtn').onmouseout = () => header.querySelector('#clearBtn').style.color = '#64748b';
        header.querySelector('#settingsBtn').onclick = () => {
            showSettings = true;
            render();
        };
        header.querySelector('#settingsBtn').onmouseover = () => header.querySelector('#settingsBtn').style.color = '#22d3ee';
        header.querySelector('#settingsBtn').onmouseout = () => header.querySelector('#settingsBtn').style.color = '#64748b';

        // Stats Grid
        const statsGrid = document.createElement('div');
        statsGrid.style.cssText = `display:grid;grid-template-columns:1fr 1fr;gap:0.75rem;padding:1rem;z-index:10`;

        const totalSVG = `<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#22d3ee" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="filter:drop-shadow(0 0 5px rgba(34,211,238,0.5));margin-bottom:0.5rem"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>`;
        const blockedSVG = `<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#6366f1" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="filter:drop-shadow(0 0 5px rgba(99,102,241,0.5));margin-bottom:0.5rem"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`;
        const warningsSVG = `<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#f97316" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="filter:drop-shadow(0 0 5px rgba(249,115,22,0.5));margin-bottom:0.5rem"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
        const maxRiskSVG = `<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#f43f5e" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="filter:drop-shadow(0 0 5px rgba(244,63,94,0.5));margin-bottom:0.5rem"><circle cx="12" cy="12" r="10"></circle><circle cx="12" cy="12" r="6"></circle><line x1="12" y1="1" x2="12" y2="23"></line><line x1="1" y1="12" x2="23" y2="12"></line></svg>`;

        const statBoxes = [
            { icon: totalSVG, label: 'Total Analyzed', value: stats.total, borderTop: '#22d3ee', glow: 'rgba(34,211,238,0.06)' },
            { icon: blockedSVG, label: 'Blocked', value: stats.blocked, borderTop: '#6366f1', glow: 'rgba(99,102,241,0.06)' },
            { icon: warningsSVG, label: 'Security Warnings', value: stats.alerts, borderTop: '#f97316', glow: 'rgba(249,115,22,0.06)' },
            { icon: maxRiskSVG, label: 'Max Risk', value: stats.maxScore.toFixed(2), borderTop: '#f43f5e', glow: 'rgba(244,63,94,0.06)' }
        ];

        statBoxes.forEach(stat => {
            const box = document.createElement('div');
            box.style.cssText = `background:linear-gradient(135deg, rgba(30,41,59,0.3) 0%, rgba(15,23,42,0.5) 100%);backdrop-filter:blur(12px);padding:1rem;border-radius:0.75rem;border:1px solid rgba(255,255,255,0.04);border-top:2px solid ${stat.borderTop};display:flex;flex-direction:column;align-items:center;box-shadow:0 8px 20px rgba(0,0,0,0.3), inset 0 0 10px ${stat.glow};transition:all 0.3s cubic-bezier(0.4, 0, 0.2, 1);cursor:default`;
            box.onmouseover = () => {
                box.style.transform = 'translateY(-3px)';
                box.style.boxShadow = `0 12px 24px rgba(0,0,0,0.4), inset 0 0 15px ${stat.glow}, 0 0 10px ${stat.borderTop}22`;
                box.style.borderColor = `${stat.borderTop}44`;
            };
            box.onmouseout = () => {
                box.style.transform = 'translateY(0)';
                box.style.boxShadow = `0 8px 20px rgba(0,0,0,0.3), inset 0 0 10px ${stat.glow}`;
                box.style.borderColor = 'rgba(255,255,255,0.04)';
                box.style.borderTopColor = stat.borderTop;
            };
            box.innerHTML = `
                ${stat.icon}
                <span style="font-size:24px;font-weight:900;color:white;letter-spacing:-0.02em;background:linear-gradient(to bottom,#ffffff,#cbd5e1);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text">${stat.value}</span>
                <span style="font-size:11px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;margin-top:0.5rem">${stat.label}</span>
            `;
            statsGrid.appendChild(box);
        });

        // Events List
        const eventsList = document.createElement('div');
        eventsList.style.cssText = `flex:1;overflow-y:auto;padding:1rem;position:relative;z-index:10;display:flex;flex-direction:column;gap:0.5rem`;

        const title = document.createElement('h2');
        title.style.cssText = `font-size:11px;font-weight:bold;color:#475569;text-transform:uppercase;letter-spacing:0.12em;margin:0 0.25rem 0.5rem 0.25rem`;
        title.textContent = 'Live Telemetry';
        eventsList.appendChild(title);

        if (events.length === 0) {
            const empty = document.createElement('div');
            empty.style.cssText = `text-align:center;color:#475569;margin-top:2.5rem;font-size:13px;font-style:italic`;
            empty.textContent = 'Waiting for DNS traffic...';
            eventsList.appendChild(empty);
        } else {
            events.forEach(ev => {
                const item = document.createElement('div');
                item.style.cssText = `background:rgba(30,41,59,0.25);backdrop-filter:blur(8px);cursor:pointer;padding:0.75rem;border-radius:0.5rem;border:1px solid rgba(255,255,255,0.03);display:flex;align-items:center;justify-content:space-between;font-size:14px;transition:all 0.25s cubic-bezier(0.4, 0, 0.2, 1)`;

                const hoverBorder = ev.final_score > 60 ? 'rgba(239,68,68,0.2)' : 'rgba(34,211,238,0.2)';
                item.onmouseover = () => {
                    item.style.background = 'rgba(30,41,59,0.45)';
                    item.style.borderColor = hoverBorder;
                    item.style.transform = 'translateX(4px)';
                    item.style.boxShadow = '0 4px 12px rgba(0,0,0,0.4)';
                };
                item.onmouseout = () => {
                    item.style.background = 'rgba(30,41,59,0.25)';
                    item.style.borderColor = 'rgba(255,255,255,0.03)';
                    item.style.transform = 'translateX(0)';
                    item.style.boxShadow = 'none';
                };
                item.onclick = () => {
                    selectedEvent = ev;
                    render();
                };

                const dotColor = getTierColor(ev.tier);
                item.innerHTML = `
                    <div style="display:flex;align-items:center;gap:0.75rem;overflow:hidden">
                        <div style="width:10px;height:10px;border-radius:50%;background:${dotColor};box-shadow:0 0 8px ${dotColor};flex-shrink:0;position:relative">
                            <div style="position:absolute;inset:-2px;border-radius:50%;border:1px solid ${dotColor};opacity:0.4;animation:pulse 2s infinite"></div>
                        </div>
                        <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px;font-weight:500;color:#cbd5e1">${ev.domain}</span>
                    </div>
                    <div style="display:flex;flex-direction:column;align-items:flex-end;flex-shrink:0">
                        <span style="font-family:monospace;font-weight:bold;font-size:16px;color:${ev.final_score > 60 ? '#f87171' : '#22d3ee'};text-shadow:0 0 8px ${ev.final_score > 60 ? 'rgba(248,113,113,0.2)' : 'rgba(34,211,238,0.2)'}">${ev.final_score.toFixed(2)}</span>
                        <span style="font-size:10px;color:#475569;font-weight:500">${new Date(ev.timestamp).toLocaleTimeString()}</span>
                    </div>
                `;
                eventsList.appendChild(item);
            });
        }

        // Footer
        const footer = document.createElement('footer');
        footer.style.cssText = `margin-top:auto;background:rgba(15,23,42,0.8);border-top:1px solid rgba(255,255,255,0.05);padding:0.625rem 1rem;display:flex;align-items:center;justify-content:space-between;z-index:10;overflow:hidden;backdrop-filter:blur(12px)`;
        footer.innerHTML = `
            <div style="display:flex;align-items:center;gap:0.5rem;white-space:nowrap">
                <div style="width:6px;height:6px;border-radius:50%;background:#10b981;box-shadow:0 0 6px rgba(16,185,129,0.8);position:relative">
                    <div style="position:absolute;inset:-2px;border-radius:50%;border:1px solid #10b981;opacity:0.5;animation:pulse 2s infinite"></div>
                </div>
                <span style="font-size:10px;font-weight:bold;color:#64748b;text-transform:uppercase;letter-spacing:0.05em">System: Stable</span>
            </div>
            <button id="dashboardBtn" style="font-size:10px;font-weight:900;color:#22d3ee;background:transparent;border:none;cursor:pointer;text-transform:uppercase;letter-spacing:0.08em;transition:all 0.2s;display:flex;align-items:center;gap:0.25rem">
                <span>Dashboard</span>
                <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
            </button>
        `;

        footer.querySelector('#dashboardBtn').onclick = () => window.open('http://localhost:5173');
        footer.querySelector('#dashboardBtn').onmouseover = () => {
            footer.querySelector('#dashboardBtn').style.color = '#6366f1';
            footer.querySelector('#dashboardBtn').style.textShadow = '0 0 8px rgba(99,102,241,0.5)';
        };
        footer.querySelector('#dashboardBtn').onmouseout = () => {
            footer.querySelector('#dashboardBtn').style.color = '#22d3ee';
            footer.querySelector('#dashboardBtn').style.textShadow = 'none';
        };

        container.appendChild(glow1);
        container.appendChild(glow2);
        container.appendChild(header);
        container.appendChild(statsGrid);
        container.appendChild(eventsList);
        container.appendChild(footer);
        root.appendChild(container);
    }
}

// Initialize
loadEvents();
render();
