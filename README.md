# PhishGuard AI 🛡️
> **"Detect the Threat. Protect Your Digital World."**

PhishGuard AI is an advanced, production-quality phishing URL risk assessment system engineered for academic evaluation (MCA Capstone). It couples an offline, genuinely trained machine learning classifier (Random Forest) with optional multi-source threat intelligence feeds (Google Safe Browsing v4 and abuse.ch URLhaus).

---

## 🚀 Key Highlights

- **Genuine Machine Learning Engine:** Evaluates URLs across 16 lexical and structural security dimensions with calibrated probability scoring and heuristic anomaly explanations.
- **Zero-Network Ingestion Guarantee:** Strictly treats all incoming URLs as untrusted strings. Zero external crawls, zero rendering, zero backend DNS resolution. 100% immune to SSRF.
- **Optional Threat Intelligence:** Decoupled server-side adapters for Google Safe Browsing and abuse.ch URLhaus with independent status tracking (`Not Configured`, `No Match Reported`, `Threat Reported`, `Unavailable`).
- **Cybersecurity SaaS Aesthetics:** Engineered with a strict dark palette (#050505 foundation, #39FF88 neon green, #FFD54A warning yellow, #FF525C danger red). **100% free of blue or purple.**
- **Real-Time Analytics & Persistence:** Powered by SQLite and SQLAlchemy. Real-time stats, paginated scan history, and RFC 4180 CSV export.
- **Academic Transparency (ML Lab):** Complete model transparency displaying genuine training metrics, confusion matrix, ROC-AUC, and feature importances.

---

## 🛠️ Architecture & Tech Stack

```
phishguard-ai/
├── backend/            # FastAPI REST backend, SQLite models, Threat Intel adapters
│   ├── app/
│   │   ├── api/        # REST routes (/api/v1/scan, /scans, /analytics, etc.)
│   │   ├── core/       # Config, CORS, security constants
│   │   ├── db/         # SQLite engine and session management
│   │   ├── models/     # SQLAlchemy ORM models
│   │   ├── schemas/    # Pydantic validation schemas
│   │   ├── services/   # Inference service & Threat Intel aggregator
│   │   ├── ml/         # Model loader and feature extractor
│   │   └── utils/      # URL normalizer and sanitizers
│   └── tests/          # Comprehensive Pytest suite
├── frontend/           # React + Vite + TypeScript + Tailwind CSS SPA
│   ├── src/
│   │   ├── components/ # Header, Footer, ScanResultCard, FeatureTable, etc.
│   │   ├── pages/      # Landing, Scanner, Results, Dashboard, History, MLLab, Settings
│   │   ├── services/   # Axios/Fetch API client
│   │   └── styles/     # Tailwind CSS with custom pure-black palette
├── ml/                 # Machine learning pipeline
│   ├── data/           # Dataset storage and benchmark sources
│   ├── artifacts/      # Serialized .joblib model & metadata JSON
│   ├── reports/        # Training and evaluation reports
│   ├── feature_extraction.py # Reusable feature extraction engine
│   └── train.py        # Model training, comparison and evaluation script
└── docs/               # Full academic documentation suite
```

---

## ⚡ Quick Start (Windows 11)

### 1. Train Machine Learning Model
```powershell
python ml/train.py
```

### 2. Run the Backend API (FastAPI)
```powershell
cd backend
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### 3. Run the Frontend (React + Vite)
```powershell
cd frontend
npm install
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## 📖 Comprehensive Documentation
- [System Requirements Specification](file:///C:/Users/shett/.gemini/antigravity-ide/scratch/phishguard-ai/docs/SYSTEM_REQUIREMENTS.md)
- [System Architecture & Data Flows](file:///C:/Users/shett/.gemini/antigravity-ide/scratch/phishguard-ai/docs/SYSTEM_ARCHITECTURE.md)
- [Database Design & Schema](file:///C:/Users/shett/.gemini/antigravity-ide/scratch/phishguard-ai/docs/DATABASE_DESIGN.md)
- [ML Methodology & Feature Engineering](file:///C:/Users/shett/.gemini/antigravity-ide/scratch/phishguard-ai/docs/ML_METHODOLOGY.md)
- [REST API Documentation](file:///C:/Users/shett/.gemini/antigravity-ide/scratch/phishguard-ai/docs/API_DOCUMENTATION.md)
- [Threat Intelligence Integration Guide](file:///C:/Users/shett/.gemini/antigravity-ide/scratch/phishguard-ai/docs/THREAT_INTELLIGENCE.md)
- [Testing Report & Strategy](file:///C:/Users/shett/.gemini/antigravity-ide/scratch/phishguard-ai/docs/TESTING_REPORT.md)
- [Setup & Deployment Guide](file:///C:/Users/shett/.gemini/antigravity-ide/scratch/phishguard-ai/docs/DEPLOYMENT_GUIDE.md)
- [Academic Viva Questions & Answers (25 Q&As)](file:///C:/Users/shett/.gemini/antigravity-ide/scratch/phishguard-ai/docs/VIVA_QUESTIONS.md)
