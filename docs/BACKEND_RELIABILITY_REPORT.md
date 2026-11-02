# PhishGuard AI — Backend & Database Reliability Architecture Report

**Report Date:** November 2026  
**Status:** Validated & Production Ready  
**Scope:** Concurrency, Database Connection Pooling, SQLite WAL Mode, Alembic Schema Evolution & Process Lifecycle

---

## 1. Database Architecture & Concurrency Strategy

PhishGuard AI supports dual database engines:
1. **Production: Managed PostgreSQL (e.g. Neon Serverless / AWS RDS)**
   - Pre-ping pool verification (`pool_pre_ping: True`) to automatically recover from stale serverless connections.
   - Connection pool size: 10 base connections + 20 max overflow.
   - Connection recycling: 300 seconds (`pool_recycle: 300`) to eliminate TCP dropouts.
   - SSL encryption enforced (`sslmode: require`).
2. **Local / Single-Node / Edge: Embedded SQLite**
   - **Write-Ahead Logging (WAL) Mode:** `PRAGMA journal_mode=WAL` enables non-blocking concurrent readers while a write is occurring.
   - **Busy Timeout:** `PRAGMA busy_timeout=5000` instructs the driver to wait up to 5 seconds if a write lock is temporarily held, completely eliminating `sqlite3.OperationalError: database is locked`.
   - **Normal Sync:** `PRAGMA synchronous=NORMAL` optimizes disk I/O throughput safely under WAL.

---

## 2. Process Lifecycle & Thread Safety

### 2.1 Lifespan Management
FastAPI modern lifespan handler (`@asynccontextmanager`) in `app/main.py`:
- **Startup:**
  1. `init_db()` verifies table existence and runs backwards-compatible schema adjustments.
  2. `start_feed_refresh()` initializes periodic local threat feed synchronization with ETags.
  3. `ThreatIntelAggregator.refresh_probes_background()` pre-populates external provider status.
  4. `MLInferenceService.load()` unpickles the Random Forest model artifact in memory, preventing request-time cold start latency.
- **Shutdown:**
  1. `ThreatIntelAggregator.shutdown(timeout=1.0)` gracefully joins in-flight background worker threads.
  2. Suppresses `httpx` HTTP request logging in background tasks to prevent `ValueError: I/O operation on closed file` during process teardown.

---

## 3. Database Schema Integrity & Migration Management

The database models are declaratively defined:
- `users`: User identity, Argon2id password hash, full name, email, created timestamp.
- `user_sessions`: Server-side sessions, SHA-256 hashed session token, CSRF token, user agent, client IP, expiration, remember flag.
- `scan_history`: User-isolated scan records with JSON feature vector, risk level, predicted class, and probability.
- `threat_check_logs`: Detailed breakdown of every threat provider checked for each scan.
- `domain_age_cache`: 7-day SQLite cache for RDAP domain registration lookups.
- `model_metadata`: Synced snapshot of ML algorithm metrics, confusion matrix, and feature importances.

