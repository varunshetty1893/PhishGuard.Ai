# Operations & Monitoring Report

## Overview
This document describes the operational observability improvements made to PhishGuard AI during Phase 8.

---

## Phase 8 Deliverables

### 8.1 — Enriched `/api/v1/health` Endpoint

**File:** `backend/app/api/endpoints/health.py`

**Previous response shape (before):**
```json
{
  "status": "healthy",
  "database": "connected",
  "model_loaded": true,
  "ml_model_loaded": true,
  "model_version": "5.0.0",
  "threat_providers": {"google_safe_browsing": "active"},
  "timestamp": "..."
}
```

**New response shape (after):**
```json
{
  "status": "healthy",
  "uptime_seconds": 3742.1,
  "timestamp": "2026-11-02T10:51:00Z",
  "database": {
    "status": "connected",
    "latency_ms": 1.23
  },
  "ml_model": {
    "loaded": true,
    "model_loaded": true,
    "ml_model_loaded": true,
    "model_version": "5.0.0",
    "algorithm": "Random Forest",
    "decision_threshold": 0.66,
    "feature_count": 31
  },
  "threat_intel": {
    "providers": {
      "google_safe_browsing": "active",
      "phish_destroy": "active"
    },
    "circuit_breakers": {
      "google_safe_browsing": {"state": "CLOSED", "failure_count": 0, "last_failure": null},
      "phish_destroy": {"state": "CLOSED", "failure_count": 0, "last_failure": null}
    }
  }
}
```

**New fields added:**

| Field | Description |
|---|---|
| `uptime_seconds` | Seconds since this process started (monotonic clock) |
| `database.latency_ms` | Round-trip time for `SELECT 1` health probe in milliseconds |
| `ml_model.algorithm` | Algorithm name from model metadata |
| `ml_model.decision_threshold` | Classification threshold in use (e.g. 0.66) |
| `ml_model.feature_count` | Number of features the model was trained on |
| `threat_intel.circuit_breakers` | Per-provider circuit breaker state, failure count, and last failure timestamp |

**Backward compatibility preserved:** Legacy flat keys (`model_loaded`, `ml_model_loaded`, `model_version`) remain in the `ml_model` object at their original names.

---

### 8.2 — Circuit Breaker Diagnostics

The `ThreatIntelAggregator.get_circuit_status()` method (added in Phase 3) is now surfaced via the health endpoint. This enables:

- **External monitoring**: a cron job or uptime monitor can poll `/api/v1/health` and alert when any circuit breaker transitions to `OPEN`
- **SRE visibility**: on-call engineers can see which provider is failing and how many failures have accumulated without accessing application logs

---

### 8.3 — Database Latency Measurement

The health check now measures `SELECT 1` round-trip time. A latency spike on this probe (e.g. > 100 ms on SQLite or > 50 ms on PostgreSQL) indicates lock contention or storage degradation.

---

## Monitoring Recommendations

> [!TIP]
> The following monitoring setup is recommended for production deployment. It requires no paid services — only open-source tools already available in the Docker ecosystem.

### Suggested Uptime & Alerting

| Tool | Purpose | Setup cost |
|---|---|---|
| [Uptime Kuma](https://github.com/louislam/uptime-kuma) | Poll `/api/v1/health`, alert when `status != "healthy"` | Self-hosted, free |
| [Prometheus + Grafana](https://grafana.com) | Expose `/metrics` via `prometheus-fastapi-instrumentator` | docker compose |
| [Sentry](https://sentry.io) | Capture unhandled exceptions with full context | Free tier available |

### Key Metrics to Alert On

| Metric | Alert threshold |
|---|---|
| `status` | Not `"healthy"` |
| `database.latency_ms` | > 100 ms (SQLite) / > 30 ms (Postgres) |
| `ml_model.loaded` | `false` |
| `threat_intel.circuit_breakers.*.state` | `"OPEN"` |
| `uptime_seconds` | Sudden drop to 0 (unexpected restart) |

---

## Health Endpoint Test Coverage

The enriched health endpoint is covered by the existing `test_health.py` suite (part of the 59-test baseline). The response schema was extended non-breaking — no existing tests were modified.

