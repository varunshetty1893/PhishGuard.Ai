# Neon PostgreSQL Setup Guide — PhishGuard AI

PhishGuard AI supports **Neon Serverless PostgreSQL** for production deployment and high-throughput concurrent scan processing, alongside local SQLite fallback for offline development and testing.

---

## 1. Get Your Neon PostgreSQL Connection String

1. Log into your [Neon Console](https://console.neon.tech).
2. Create or select your project (e.g., `phishguard-db`).
3. Under **Dashboard > Connection Details**, select:
   - **Connection string**
   - Protocol: `postgres` / `postgresql`
   - Mode: **Pooled** (Recommended for serverless FastAPI concurrency)
4. Copy the connection URI:
   ```text
   postgresql://<user>:<password>@<ep-pooler-xyz>.region.aws.neon.tech/neondb?sslmode=require
   ```

---

## 2. Configure Environment Variable

Create or update your `backend/.env` file:

```env
# Database Connection (Neon PostgreSQL)
DATABASE_URL=postgresql://neondb_owner:npg_YourPassword@ep-cool-resonance-123456-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require

# Application Mode
ENVIRONMENT=production
PORT=8000
COOKIE_SECURE=true

# Security Secrets
SECRET_KEY=generate_a_long_random_64_character_hex_secret

# Optional Threat Intelligence API Keys
GOOGLE_SAFE_BROWSING_API_KEY=
```

PhishGuard's OpenPhish, Phishing.Database, and CERT-PL Warning List feeds and
PhishDestroy checks do not require API keys. CERT-PL focuses on dangerous sites
targeting Polish users. A feed/provider error is reported as unavailable, never
as a clean lookup.

> **Note**: PhishGuard AI automatically parses both `postgres://` and `postgresql://` formats, enables `pool_pre_ping=True` to eliminate stale connections, and enforces `sslmode=require`.

---

## 3. Apply Migrations to Neon

To initialize the schema on your Neon PostgreSQL instance:

```bash
# Option A: Run Alembic migration
alembic upgrade head

# Option B: Automatic Startup Initialization
# Starting the FastAPI server automatically triggers init_db() which creates all tables:
python -m uvicorn app.main:app
```

---

## 4. Tables Created in Neon PostgreSQL

1. **`users`**:
   - `id`: Serial Primary Key
   - `full_name`: VARCHAR(100)
   - `email`: VARCHAR(255) (Unique Index, normalized)
   - `password_hash`: VARCHAR(255) (Argon2id hash)
   - `account_status`: VARCHAR(20) (`active`, `suspended`)
   - `created_at`, `updated_at`: TIMESTAMP WITH TIME ZONE

2. **`user_sessions`**:
   - `id`: Serial Primary Key
   - `session_token`: VARCHAR(64) (Cryptographically secure unique index)
   - `csrf_token`: VARCHAR(64)
   - `user_id`: Foreign Key referencing `users(id)` ON DELETE CASCADE
   - `ip_address`, `user_agent`: Client metadata
   - `created_at`, `expires_at`, `last_active_at`: TIMESTAMP WITH TIME ZONE

3. **`scan_history`**:
   - `id`: Serial Primary Key
   - `scan_id`: UUID (Unique Index)
   - `user_id`: Foreign Key referencing `users(id)` ON DELETE CASCADE (Enforces strict data isolation)
   - `submitted_url`, `normalized_url`, `predicted_class`, `risk_level`, `model_score`
   - `extracted_features_json`, `suspicious_reasons_json`, `combined_interpretation`
   - `model_version`, `created_at`

4. **`threat_check_logs`**:
   - `id`: Serial Primary Key
   - `scan_id`: Foreign Key referencing `scan_history(scan_id)` ON DELETE CASCADE
   - `provider_name`, `check_status`, `threat_found`, `threat_category`, `raw_response`, `error_message`, `checked_at`

5. **`model_metadata`**:
   - Audit trail, dataset provenance, and ML evaluation metrics.
