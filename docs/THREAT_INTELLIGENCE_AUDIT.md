# PhishGuard AI — Threat Intelligence Architecture & Resilience Audit

**Audit Date:** November 2026  
**Component:** Threat Intelligence Aggregation, Circuit Breaker Pattern & Local Feeds  
**Status:** Hardened & Production Ready

---

## 1. Overview & Architecture

PhishGuard AI employs a defense-in-depth, multi-layered threat intelligence system combining local high-speed feeds with upstream external reputation APIs.

### 1.1 Provider Taxonomy
1. **Local SQLite Feeds (Zero Outbound Crawl / Low Latency $\le 2\text{ ms}$):**
   - **OpenPhish Public Community Feed:** Active targeted URLs, refreshed every 6 hours with ETag caching.
   - **Phishing.Database (Active URLs & Active Domains):** Hundreds of thousands of active indicators parsed into indexed SQLite tables.
   - **CERT-PL Domain Warning List:** Polish Computer Emergency Response Team verified malicious registry, refreshed every 5 minutes.
2. **Upstream API Adapters (Controlled & Protected):**
   - **Google Safe Browsing v4 (Lookup API):** Enterprise threat intelligence with URL path minimization to protect end-user privacy.
   - **PhishDestroy Public API:** Reputation lookup querying domain-level flags.

---

## 2. Hardening Measures Implemented

### 2.1 Circuit Breaker Pattern
To prevent external latency degradation or upstream outages from blocking client scan requests, `CircuitBreaker` is implemented on all upstream network adapters:
- **State Machine:** `CLOSED` $\rightarrow$ `OPEN` $\rightarrow$ `HALF_OPEN`.
- **Thresholds:**
  - `failure_threshold`: 3 consecutive failures (HTTP 5xx, network timeout, connection drop).
  - `recovery_timeout`: 60.0 seconds cooldown.
  - `timeout`: 3.0 seconds per request (reduced from legacy 8.0s).
- **Behavior under Outage:**
  When a provider experiences 3 timeouts or network errors, the breaker trips to `OPEN`. Subsequent requests bypass that provider immediately in $0.0\text{ ms}$, returning `status: "Unavailable (Circuit Breaker OPEN)"` without blocking the pipeline.

### 2.2 Privacy URL Minimization
- Google Safe Browsing: Query parameters and fragments are stripped prior to dispatch (`scheme://netloc/path`), preventing user session tokens or PII in URLs from leaking to third parties.
- PhishDestroy: Only the clean registered hostname is dispatched; entire path and query are omitted.

### 2.3 Stale-While-Revalidate Status Caching
Provider status for system health checks (`/api/v1/health`) uses background worker threads with thread locks and TTL caching (5 minutes), completely eliminating blocking I/O on health check requests.
Application shutdown in `main.py` lifespan explicitly invokes `ThreatIntelAggregator.shutdown()` to ensure background threads join cleanly without I/O errors.

