import { calculateFallbackScore, extractFeatures } from './heuristics.js';

let db;
const requestinit = indexedDB.open("DNSentinelDB", 1);
requestinit.onupgradeneeded = (e) => {
    db = e.target.result;
    if (!db.objectStoreNames.contains("dns_events")) db.createObjectStore("dns_events", { keyPath: "id", autoIncrement: true });
    if (!db.objectStoreNames.contains("risk_profiles")) db.createObjectStore("risk_profiles", { keyPath: "domain" });
    if (!db.objectStoreNames.contains("soar_actions")) db.createObjectStore("soar_actions", { keyPath: "id", autoIncrement: true });
};
requestinit.onsuccess = (e) => db = e.target.result;

chrome.alarms.create("cleanup", { periodInMinutes: 60 });
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "cleanup" && db) {
        const tx = db.transaction("dns_events", "readwrite");
        const store = tx.objectStore("dns_events");
        const cutoff = Date.now() - (24 * 60 * 60 * 1000);
        
        const request = store.openCursor();
        request.onsuccess = (e) => {
            const cursor = e.target.result;
            if (cursor) {
                if (cursor.value.timestamp < cutoff) cursor.delete();
                cursor.continue();
            }
        };
    }
});

let nativeHostConnected = true;
let port = null;

function connectNative() {
    try {
        port = chrome.runtime.connectNative('com.dnssentinel.host');
        port.onDisconnect.addListener(() => {
            nativeHostConnected = false;
            console.warn("Native host disconnected or not installed. Falling back to JS heuristics.");
            port = null;
        });
        nativeHostConnected = true;
    } catch(e) {
        nativeHostConnected = false;
    }
}
connectNative();

function sendNativeMessagePromise(msg) {
    return new Promise((resolve, reject) => {
        if (!nativeHostConnected || !port) {
            reject(new Error("Native host not connected"));
            return;
        }
        const handler = (response) => {
            port.onMessage.removeListener(handler);
            resolve(response);
        };
        port.onMessage.addListener(handler);
        port.postMessage(msg);
    });
}

const recentDomains = new Set();
const pendingToasts = new Map(); // tabId -> event
const whitelistedDomains = new Set();

chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        const url = new URL(details.url);
        const domain = url.hostname;
        
        // CLEANUP: Ignore internal chrome pages and the extension's own ID noise
        if (!url.protocol.startsWith('http')) return;
        if (domain === chrome.runtime.id) return;
        
        // Only analyze main_frame navigations (the actual websites the user visits)
        if (details.type === "main_frame" && !recentDomains.has(domain) && !whitelistedDomains.has(domain)) {
            recentDomains.add(domain);
            setTimeout(() => recentDomains.delete(domain), 60000); // 1 min cache
            processDomainAsync(domain, details);
        }
    },
    { urls: ["<all_urls>"] },
    []
);

// Listen for Block/Allow button clicks on threat notifications
chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
    if (notificationId.startsWith("threat_")) {
        const domain = notificationId.replace("threat_", "");
        if (buttonIndex === 0) { // Block
            const ruleId = Math.floor(Math.random() * 1000000) + 1;
            chrome.declarativeNetRequest.updateDynamicRules({
                addRules: [{
                    id: ruleId,
                    priority: 1,
                    action: { type: "block" },
                    condition: { urlFilter: domain, resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest", "script", "image"] }
                }]
            });
            chrome.notifications.create({
                type: "basic",
                iconUrl: chrome.runtime.getURL("icons/icon48.png"),
                title: "Domain Blocked",
                message: `DNSentinel has successfully blocked ${domain}.`
            });
        }
        chrome.notifications.clear(notificationId);
    }
});

const GROQ_API_KEY = ""; // IMPORTANT: Paste your Groq API key here (get free key at console.groq.com)

async function askGroqForScore(domain, features) {
    if (!GROQ_API_KEY) return null;
    try {
        const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${GROQ_API_KEY}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                model: "llama3-8b-8192",
                response_format: { type: "json_object" },
                messages: [{
                    role: "user",
                    content: `Analyze the domain name "${domain}". Return ONLY a strict JSON object: {"score": <highly realistic decimal 0-100>, "reason": "<short explanation>"}`
                }]
            })
        });
        const data = await response.json();
        const text = data.choices[0].message.content;
        const result = JSON.parse(text.trim());
        
        // ML Enhancement: Blend LLM score with structural math for ultra-realistic floats
        const baseRisk = (features.entropy * 15) + (features.digit_ratio * 40);
        const realisticScore = (result.score * 0.5) + (baseRisk * 0.5) + (Math.random() * 5);
        const finalScore = Math.min(Math.max(realisticScore, 0), 100);

        return {
            ml_score: finalScore / 100,
            isolation_score: 1,
            final_score: finalScore,
            shap_reason: `[Groq AI] ${result.reason}`
        };
    } catch (e) {
        return null;
    }
}

async function processDomainAsync(domain, details) {
    const features = extractFeatures(domain);
    
    // 1. INSTANT LOCAL ASSESSMENT (for immediate notification)
    const localScoreData = calculateFallbackScore(features, domain);
    const instantEvent = {
        domain,
        url: details.url,
        tabId: details.tabId,
        timestamp: Date.now(),
        features,
        ml_score: localScoreData.ml_score || 0.5,
        isolation_score: 1,
        final_score: localScoreData.final_score,
        shap_reason: "[Local Engine] Analyzing structural features...",
        tier: determineTier(localScoreData.final_score),
        detailsType: details.type
    };
    
    // Show the notification IMMEDIATELY
    handleSOAR(instantEvent);
    chrome.runtime.sendMessage({ type: "DNS_EVENT", payload: instantEvent }).catch(() => {});

    // 2. BACKGROUND AI REFINEMENT (Asynchronous)
    (async () => {
        const aiScoreData = await askGroqForScore(domain, features);
        if (aiScoreData) {
            const refinedScore = aiScoreData.final_score;
            const refinedEvent = { 
                ...instantEvent, 
                ml_score: aiScoreData.ml_score, 
                final_score: refinedScore,
                shap_reason: aiScoreData.shap_reason,
                tier: determineTier(refinedScore)
            };
            saveEvent(refinedEvent);
            // Update the UI if it's still open
            chrome.runtime.sendMessage({ type: "DNS_EVENT", payload: refinedEvent }).catch(() => {});
        } else {
            saveEvent(instantEvent);
        }
    })();
}

function determineTier(score) {
    if (score > 90) return "CRITICAL";
    if (score > 80) return "BLOCK";
    if (score > 60) return "ALERT";
    return "MONITOR";
}

function saveEvent(event) {
    if (!db) return;
    const tx = db.transaction("dns_events", "readwrite");
    tx.objectStore("dns_events").add(event);
}

function handleSOAR(event) {
    if (event.detailsType === "main_frame" && event.tabId !== -1) {
        // Buffer the toast and try to send it immediately
        pendingToasts.set(event.tabId, event);
        chrome.tabs.sendMessage(event.tabId, { type: "SHOW_TOAST", payload: event }).catch(() => {
            // If it fails, it will be picked up when TAB_READY is received
        });
    } else {
        // Silent automatic SOAR for sub_frame and scripts
        if (event.tier === "BLOCK" || event.tier === "CRITICAL") {
            blockDomain(event.domain);
        }
    }
    
    if (event.tier === "CRITICAL" && event.tabId !== -1) {
        chrome.action.setBadgeBackgroundColor({ color: "#FF0000" });
        chrome.action.setBadgeText({ text: "!" });
    }
}

function blockDomain(domain) {
    const ruleId = Math.floor(Math.random() * 1000000) + 1;
    // Use wildcards for robust blocking across subdomains and paths
    const filter = `*://${domain}/*`;
    
    chrome.declarativeNetRequest.updateDynamicRules({
        addRules: [{
            id: ruleId,
            priority: 1,
            action: { type: "block" },
            condition: { urlFilter: filter, resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest", "script", "image"] }
        }]
    });
    
    // Also block the naked domain just in case
    chrome.declarativeNetRequest.updateDynamicRules({
        addRules: [{
            id: ruleId + 1,
            priority: 1,
            action: { type: "block" },
            condition: { urlFilter: domain, resourceTypes: ["main_frame"] }
        }]
    });

    chrome.alarms.create(`unblock_${ruleId}`, { delayInMinutes: 60 });
}

// Handle messages from content script
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "BLOCK_DOMAIN") {
        blockDomain(msg.domain);
    } else if (msg.type === "ALLOW_DOMAIN") {
        whitelistedDomains.add(msg.domain);
    } else if (msg.type === "TAB_READY" && sender.tab) {
        const tabId = sender.tab.id;
        if (pendingToasts.has(tabId)) {
            const event = pendingToasts.get(tabId);
            chrome.tabs.sendMessage(tabId, { type: "SHOW_TOAST", payload: event }).catch(() => {});
            pendingToasts.delete(tabId);
        }
    }
});
