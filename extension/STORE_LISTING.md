# DNSentinel: ML-Based Browser Security

## Chrome Web Store Description

DNSentinel is an ML-based DNS threat detection and exfiltration monitoring tool, available natively in your browser.

Traditional DNS protection relies on static blacklists. DNSentinel uses advanced Machine Learning (Random Forest & Isolation Forest) combined with behavioral heuristics to detect and block zero-day threats, DNS tunneling, and Domain Generation Algorithms (DGAs) in real-time.

**Key Features:**
- **Zero-Trust DNS Analysis:** Analyzes the entropy, character density, and structural characteristics of every domain you connect to.
- **ML (Native Bridge):** Optionally connects to a local Python Native Messaging Host to run heavy ML models without sending data to the cloud.
- **Offline Fallback:** Features a robust JS heuristic engine that provides protection even if the Native Host is disconnected.
- **SOAR Orchestration:** Automatically categorizes threats into Monitor, Alert, Block, or Critical tiers, taking immediate action to protect your session.
- **XAI Explainability:** Understand exactly *why* a domain was blocked with SHAP (SHapley Additive exPlanations).
- **Forensic Dashboard:** A built-in DevTools panel providing a SOC-style view of all intercepted traffic.

---

## Privacy Policy & Data Usage

DNSentinel prioritizes your privacy. **No browsing data is ever sent to a remote server.**
- **Local Processing:** All heuristic analysis and ML inference occurs entirely on your local machine.
- **Native Host:** If installed, the native host receives domain features via secure standard I/O streams and returns a score locally.
- **No Tracking:** We do not collect telemetry, usage stats, or analytics.

## Permission Justifications

To function properly and pass Web Store review, DNSentinel requires the following permissions:
- `declarativeNetRequest`: To dynamically block domains identified as HIGH or CRITICAL risk without causing latency.
- `webRequest`: To inspect outbound network requests and extract hostnames for analysis before a connection is established.
- `storage`: To persist user settings, risk thresholds, and locally cache recent DNS events (IndexedDB).
- `notifications`: To alert the user when an active threat is neutralized.
- `nativeMessaging`: To communicate with the optional Python ML engine installed on the user's local machine.
- `tabs` & `activeTab`: To close tabs associated with CRITICAL threats and identify the source of suspicious requests.
- `host_permissions` (`<all_urls>`): Required to analyze all domains the browser attempts to resolve.
