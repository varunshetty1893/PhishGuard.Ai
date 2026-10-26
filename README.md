# PhishGuard AI

> **AI-powered phishing URL detection** — Real Random Forest model trained on 300,000+ URLs with 96%+ accuracy

[![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)](https://react.dev)
[![Scikit-learn](https://img.shields.io/badge/scikit--learn-1.6-F7931E?logo=scikit-learn)](https://scikit-learn.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## Overview

PhishGuard AI is a full-stack cybersecurity application that detects phishing URLs in real time using a genuine machine learning pipeline — not rule lists or third-party APIs.

- **Frontend**: React 18 + TypeScript + Vite
- **Backend**: FastAPI (Python 3.12) with JWT authentication
- **ML Model**: Random Forest trained on 300,000+ real URLs from two public datasets
- **Database**: Neon PostgreSQL (production) / SQLite (local dev fallback)
- **Auth**: bcrypt password hashing, HttpOnly cookie-based JWT sessions

---

## ML Model

| Metric | Value |
|--------|-------|
| Accuracy | ≥ 96% |
| ROC-AUC | ≥ 98.9% |
| Training samples | 300,000+ unique URLs |
| Test samples | 20% stratified holdout |
| Cross-validation | 5-fold on training set |
| Features | 16 lexical/structural URL features |

**Datasets used:**
- [PhiUSIIL Phishing URL Dataset](https://www.kaggle.com/datasets/harisudhan411/phishing-and-legitimate-urls) — 235,795 URLs
- URL Features Extracted Dataset — 101,219 URLs

---

## Features

- Real-time URL scan with probability score and risk level (Safe / Suspicious / Malicious)
- Detailed feature breakdown per scan (16 features shown to user)
- Personal scan history with delete, CSV export
- Per-user analytics dashboard
- Optional Google Safe Browsing + URLhaus threat intel integration
- Full user isolation — IDOR-safe, no cross-user data leakage
- Neon PostgreSQL ready with automatic SQLite fallback for local dev

---

## Quick Start

### Prerequisites
- Python 3.12+
- Node.js 20+
- Git LFS (git lfs install)

### Backend
`ash
cd backend
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
# copy and edit .env
copy .env.example .env
# start
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
`

### Frontend
`ash
cd frontend
npm install
npm run dev
`

App runs at http://127.0.0.1:5173

---

## Environment Variables (ackend/.env)

| Variable | Required | Description |
|----------|----------|-------------|
| DATABASE_URL | No (defaults to SQLite) | Neon PostgreSQL connection string |
| SECRET_KEY | Yes | 64-char hex JWT signing secret |
| COOKIE_SECURE | No (default alse) | Set 	rue on HTTPS deployment |
| GOOGLE_SAFE_BROWSING_API_KEY | No | Enables Google threat intel |
| URLHAUS_AUTH_KEY | No | Enables URLhaus lookups |

---

## Retrain the Model

`ash
# Place raw dataset CSVs in dataset/ folder, then:
python ml/train_fulldata.py
`

See [ml/data/PROVENANCE.md](ml/data/PROVENANCE.md) for dataset details.

---

## Project Structure

`
phishguard-ai/
├── backend/              # FastAPI backend
│   ├── app/
│   │   ├── api/          # API routes (auth, scan, analytics, export)
│   │   ├── core/         # Config, security, JWT
│   │   ├── db/           # SQLAlchemy session + Alembic migrations
│   │   ├── ml/           # Feature extractor + model inference
│   │   └── models/       # ORM models (User, ScanHistory)
│   ├── alembic/          # DB migration scripts
│   └── tests/            # 29 passing pytest tests
├── frontend/             # React + TypeScript + Vite
│   └── src/
│       ├── components/
│       ├── context/      # AuthContext
│       ├── pages/        # Landing, Login, Register, Dashboard, MLLab, About
│       └── services/
├── ml/                   # Training pipeline
│   ├── train_fulldata.py # Full-data retrain script
│   ├── artifacts/        # Model + metadata (Git LFS)
│   ├── data/             # Processed dataset (gitignored, see PROVENANCE.md)
│   └── reports/          # Evaluation reports
└── dataset/              # Raw source CSVs (gitignored — too large)
`

---

## License
MIT License — see [LICENSE](LICENSE)
