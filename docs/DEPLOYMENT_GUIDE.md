# PhishGuard AI — Setup & Deployment Guide

## 1. System Requirements
- **Operating System:** Windows 11 / Windows 10 (or Linux / macOS)
- **Python:** Python 3.10 to 3.12 (Python 3.12.8 verified)
- **Node.js:** Node.js v20.x or v22.x+ (v24.16.0 verified) & npm 10+
- **Memory:** Minimum 4 GB RAM (8 GB recommended)
- **Disk Space:** ~500 MB free disk space

---

## 2. Local Windows 11 Step-by-Step Setup

### Step 2.1: Clone or Navigate to the Repository
Open PowerShell or Command Prompt:
```powershell
cd C:\Users\shett\.gemini\antigravity-ide\scratch\phishguard-ai
```

### Step 2.2: Setup Python Environment & Backend Dependencies
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 2.3: Train Machine Learning Model (First-Time Initialization)
From the project root:
```powershell
python ml/train.py
```
This trains the Random Forest and Logistic Regression models on the curated benchmark dataset, computes real evaluation metrics, and serializes the artifacts:
- `ml/artifacts/phishguard_rf_model.joblib`
- `ml/artifacts/model_metadata.json`

### Step 2.4: Configure Environment Variables (Optional)
Copy the example environment file:
```powershell
cd backend
copy .env.example .env
```
Default content of `.env`:
```ini
ENVIRONMENT=development
PORT=8000
DATABASE_URL=sqlite:///./phishguard.db
# Optional External Threat Intelligence Keys (Leave blank for default offline operation)
GOOGLE_SAFE_BROWSING_API_KEY=
URLHAUS_AUTH_KEY=
```
*Note: If keys are left blank, PhishGuard AI runs with 100% functionality using the ML model.*

### Step 2.5: Launch the FastAPI Backend
```powershell
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
The backend API is now running at `http://127.0.0.1:8000`.
- API Docs: `http://127.0.0.1:8000/docs`
- Health: `http://127.0.0.1:8000/api/v1/health`

### Step 2.6: Setup & Launch the React Frontend
Open a second PowerShell terminal:
```powershell
cd C:\Users\shett\.gemini\antigravity-ide\scratch\phishguard-ai\frontend
npm install
npm run dev
```
The frontend interface is now running at `http://localhost:5173`.

---

## 3. Running Automated Tests
To execute all backend, ML, security, and threat-intelligence unit tests:
```powershell
cd backend
pytest -v
```

---

## 4. Production Cloud Deployment Notes

### 4.1 Free-Tier Deployment Analysis
- **Frontend Hosting:** Vercel or Netlify (Free hobby tiers support static Vite build artifacts `frontend/dist`).
- **Backend API:** Render.com, Railway, or Fly.io:
  - *Render Free Web Services:* Spins down after 15 minutes of inactivity (cold start ~50s). Ephemeral disk wipes SQLite file on restarts unless a persistent disk is attached or a managed PostgreSQL instance is used.
  - *Fly.io:* Provides 256MB micro VMs with volume attachment support.
- **Academic Recommendation:** Run locally via Windows 11 PowerShell for live examiner viva demonstrations to guarantee 0ms cold starts, full SQLite persistence, and zero cloud quota restrictions.
