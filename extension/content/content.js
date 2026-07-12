// DNSentinel Content Script
// Runs at document_start to capture inline data and provide early context

let initiator = window.location.origin;

// Optionally observe dynamically inserted scripts/iframes that might bypass declarative blocking
const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
        if (mutation.addedNodes.length) {
            mutation.addedNodes.forEach(node => {
                if (node.tagName === 'SCRIPT' && node.src) {
                    try {
                        const url = new URL(node.src);
                        if (url.hostname.length > 30 || /\d{5,}/.test(url.hostname)) {
                            // Let background worker know about suspicious dynamic script insertion
                            chrome.runtime.sendMessage({
                                type: "SUSPICIOUS_NODE",
                                payload: { url: node.src, origin: initiator }
                            }).catch(() => {});
                        }
                    } catch(e) {}
                }
            });
        }
    }
});

observer.observe(document.documentElement, {
    childList: true,
    subtree: true
});

// Notify background that we are ready to receive toasts for this tab
chrome.runtime.sendMessage({ type: "TAB_READY" }).catch(() => {});

// Premium In-Page Toast Notification System
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "SHOW_TOAST") {
        showToast(msg.payload);
    }
});

function showToast(event) {
    // Only show if we are in the main window, not an iframe
    if (window.self !== window.top) return;

    // Remove existing toast if any
    const existing = document.getElementById('dnsentinel-toast');
    if (existing) existing.remove();

    const isThreat = event.tier !== "MONITOR";

    const container = document.createElement('div');
    container.id = 'dnsentinel-toast';
    // Premium glassmorphism styling
    container.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 2147483647;
        font-family: 'Inter', system-ui, -apple-system, sans-serif;
        background: ${isThreat ? 'rgba(20, 0, 0, 0.85)' : 'rgba(2, 6, 23, 0.85)'};
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid ${isThreat ? 'rgba(239, 68, 68, 0.4)' : 'rgba(34, 211, 238, 0.3)'};
        border-radius: 12px;
        padding: 16px;
        color: white;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5), inset 0 1px 0 0 rgba(255, 255, 255, 0.1);
        display: flex;
        flex-direction: column;
        gap: 12px;
        min-width: 340px;
        max-width: 400px;
        transform: translateX(120%);
        transition: transform 0.5s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.5s ease;
        opacity: 0;
    `;

    const header = document.createElement('div');
    header.style.cssText = `display: flex; align-items: center; gap: 10px;`;

    const icon = document.createElement('div');
    icon.innerHTML = isThreat ? '' : '';
    icon.style.cssText = `font-size: 20px; filter: drop-shadow(0 0 8px ${isThreat ? 'rgba(239,68,68,0.5)' : 'rgba(34,211,238,0.5)'});`;

    const title = document.createElement('div');
    title.style.cssText = `font-weight: 700; font-size: 15px; flex-grow: 1; color: ${isThreat ? '#fca5a5' : '#67e8f9'}; letter-spacing: 0.02em;`;
    title.textContent = isThreat ? 'Suspicious Website Detected' : 'DNSentinel Active';

    const closeBtn = document.createElement('button');
    closeBtn.innerHTML = '×';
    closeBtn.style.cssText = `background: none; border: none; color: #94a3b8; font-size: 22px; cursor: pointer; padding: 0 4px; line-height: 1; transition: color 0.2s;`;
    closeBtn.onmouseover = () => closeBtn.style.color = 'white';
    closeBtn.onmouseout = () => closeBtn.style.color = '#94a3b8';
    closeBtn.onclick = () => {
        container.style.transform = 'translateX(120%)';
        container.style.opacity = '0';
    };

    header.appendChild(icon);
    header.appendChild(title);
    header.appendChild(closeBtn);
    container.appendChild(header);

    const body = document.createElement('div');
    body.style.cssText = `font-size: 13.5px; color: #cbd5e1; line-height: 1.5;`;
    if (isThreat) {
        body.innerHTML = `DNSentinel flagged <strong>${event.domain}</strong> as a <span style="color:#f87171; font-weight:bold;">${event.tier}</span> risk (Score: ${(event.final_score || 0).toFixed(2)}).`;
    } else {
        body.innerHTML = `Secure connection to <strong style="color:white;">${event.domain}</strong>.`;
    }
    container.appendChild(body);

    document.body.appendChild(container);

    // Trigger animation
    requestAnimationFrame(() => {
        container.style.transform = 'translateX(0)';
        container.style.opacity = '1';
    });

    if (!isThreat) {
        setTimeout(() => {
            container.style.transform = 'translateX(120%)';
            container.style.opacity = '0';
            setTimeout(() => container.remove(), 500);
        }, 4000);
    }
}
