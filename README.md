# 🛡️ DNSentinel: Advanced DNS Threat Platform (X-DR)

**DNSentinel** is a next-generation, AI-powered cybersecurity platform designed for high-fidelity detection of **DNS Data Exfiltration**, **Tunneling**, and **DGA (Domain Generation Algorithm)** attacks. Built on an enterprise-grade stack, it combines sub-second behavioral analytics with explainable AI (XAI) to provide analysts with a fully contextualized forensic dashboard.

---

## 🏛️ System Architecture

DNSentinel follow a distributed, high-performance architecture:

-   **Backend (Python/FastAPI)**: High-throughput packet ingestion, intelligence cross-referencing, and multi-model machine learning inference.
-   **Security Store (SQLite/SQLAlchemy)**: Persistent central ledger for forensic longevity and historical threat hunting.
-   **Frontend (React/Vite/Framer Motion)**: Emotive, cinematic SOC interface featuring real-time stream processing and high-fidelity network topology graphs.
-   **Defense Layer (SOAR)**: Active response orchestrator for automated host containment and executive case reporting.

---

## 🧠 Core Intelligence Modules

### 1. Hybrid AI Detection Engine
-   **Supervised Learning (Random Forest)**: Classified against a 22-dimensional feature vector (Entropy, N-gram Density, Lexical Complexity, TLD Probability).
-   **Unsupervised Learning (Isolation Forest)**: Real-time anomaly discovery for identifying zero-day and custom tunneling patterns that deviate from local baselines.

### 2. Behavioral & Intelligence Engine
-   **Velocity Burst Discovery**: Watches for "Drip-Feed" vs. "Burst" DNS traffic structures over sliding time windows.
-   **Intel Engine**: Cross-references against malicious TLD sets and known entropy markers used in BlackHat exfiltration tools.
-   **XAI (SHAP)**: Human-readable reasoning for every malicious prediction, explaining *exactly why* the AI considers a packet suspicious.

### 3. MITRE ATT&CK Tracking
Mappings included for:
-   **T1071.004**: Application Layer Protocol: DNS
-   **T1568**: Dynamic Resolution / DGA
-   **T1041**: Exfiltration Over Command & Control

---

## 🛡️ Enterprise SOC Operations (X-DR)

### Investigation & Drills
-   **Triage Feed**: Live-streaming data grid with advanced severity filtering and sub-second sorting.
-   **Topology Map**: Circle-orbit visualization of internal assets and their external domain linkage, identifying "Hidden Callouts" at a glance.
-   **Forensic Report**: Deep-dive modal with logic-bar visualizations for AI heuristics and threat mitigation tactics.

### Active Response (SOAR)
-   **Host Containment**: One-click simulated IP blocking through the firewall orchestration layer.
-   **IR Case Generator**: Automated markdown-based Incident Reporting for executive briefings.
-   **Feedback Loop**: Human-in-the-loop retraining to eliminate false positives in specific environments.

---

## ⚙️ Deployment & Installation

### Prerequisites
-   Python 3.9+
-   Node.js 18+
-   Docker & Compose (Optional, for containerized orchestration)

### Development Setup (Local)
1.  **Backend**:
    ```bash
    cd backend
    pip install -r requirements.txt
    uvicorn main:app --reload --port 8000
    ```
2.  **Frontend**:
    ```bash
    cd frontend
    npm install
    npm run dev -- --port 5173
    ```

### Containerized Setup
Run the entire SOC stack with a single command:
```bash
docker-compose up --build
```
-   **Dashboard Access**: `http://localhost:5173`
-   **API Core**: `http://localhost:8000`

---

## 🛠️ Security Data Schema (SQLite)

| Column | Purpose |
| :--- | :--- |
| `timestamp` | UTC Event Record |
| `source_ip` | Origin Asset Identifier |
| `risk_score` | Weighted 0–100 Security Index |
| `mitre_data` | JSON Encoded ATT&CK techniques |
| `explanation` | AI-Narrated SOC Reasoning |
| `is_blocked` | Containment status (SOAR) |

---

## 📜 Credits & Research
Developed on the **Deep-Forensics Research Baseline**, integrating industry-standard **SHAP** and **Scikit-learn** methodologies for transparent security analytics.

> **IMPORTANT**: This platform is designed for research and monitoring purposes. Always coordinate with your Net-Ops team before enabling the automated containment (SOAR) functionality in live production environments.
