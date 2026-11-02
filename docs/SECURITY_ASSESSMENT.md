# PhishGuard AI — Application Security Architecture & Vulnerability Assessment

**Assessment Date:** November 2026  
**Security Level:** Production / SaaS Ready  
**Framework:** OWASP Top 10 API Security Risks (2023)

---

## 1. Security Architecture Summary

PhishGuard AI analyzes untrusted, hostile input (suspected phishing URLs) submitted by arbitrary users. The system is designed under a **Zero-Trust Input Processing Model**:
- No outbound browser rendering or headless web crawling is performed on untrusted targets.
- All structural and heuristic feature extraction is performed in-memory offline.
- Threat intelligence lookups minimize data egress to protect user privacy.
- External network interactions (DNS resolution, RDAP queries) are fenced by strict Server-Side Request Forgery (SSRF) and private address controls.

---

## 2. Threat Vector Mitigations & Verification

### 2.1 Server-Side Request Forgery (SSRF) Prevention (OWASP API7:2023)
- **Vulnerability:** Unauthenticated or authenticated users submit URLs pointing to internal services (`127.0.0.1`, `localhost`, `169.254.169.254`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, Kubernetes cluster IPs) to probe internal network topology or cloud metadata services.
- **Enforcement Layer 1 (`validate_url_security`):**
  Pre-flight check parsing the destination URI scheme, netloc, and hostname. Immediately rejects `localhost`, internal domain suffixes (`.local`, `.internal`, `.lan`), and RFC 1918 / cloud metadata IPs with `HTTP 400 Bad Request`.
- **Enforcement Layer 2 (`check_domain_dns`):**
  Performs DNS resolution inside an isolated thread with a 1.5-second timeout. Checks the resulting resolved IPv4/IPv6 address against `ipaddress.is_private`, `is_loopback`, `is_link_local`, `is_reserved`, and `is_multicast`. If an external domain resolves to an internal IP (DNS rebinding attack), it is blocked immediately.
- **Enforcement Layer 3 (`DomainAgeService`):**
  Rejects raw IP destinations and internal hosts prior to dispatching RDAP bootstrap requests.

### 2.2 Rate Limiting & Denial-of-Service Defense (OWASP API4:2023)
- **Authentication Endpoints:**
  - `/api/v1/auth/login`: Maximum 5 failed attempts per 15-minute sliding window per IP and per normalized email. Cooldown returned in standard `Retry-After` header.
  - `/api/v1/auth/register`: Maximum 10 registrations per 15-minute sliding window per IP.
- **Scan Endpoint (`/api/v1/scan`):**
  - Sliding-window rate limiting of 60 requests per 60-second window per user/IP. Prevents socket exhaustion and CPU starvation.

### 2.3 Authentication, Session & CSRF Security (OWASP API2:2023)
- **Password Storage:** Argon2id with random 16-byte salt, memory cost $65,536\text{ KiB}$ (64 MB), time cost 3 iterations.
- **Session Tokens:** Cryptographically secure 256-bit pseudorandom tokens (`secrets.token_hex(32)`) stored in database with explicit expiry.
- **Cookie Security:** HttpOnly, SameSite=Lax (Strict on sensitive actions), Secure enforced in production.
- **CSRF Defense:** Double-submit / session-bound token verification via `X-CSRF-Token` header for state-changing requests authenticated via cookies.
- **Role Isolation:** Zero client-side role privilege escalation. Role is strictly server-assigned standard user; no administrative backdoor exists.

---

## 3. Automated Security Test Verification

Automated regression tests in `backend/tests/test_security_hardening.py` confirm:
- [x] SSRF blocking of `127.0.0.1`, `localhost`, AWS metadata `169.254.169.254`, and private networks `10.0.0.1`.
- [x] Non-HTTP/HTTPS protocol injection rejection (`ftp://`, `javascript:`, `file://`).
- [x] Sliding-window rate limiting enforcement returning HTTP 429 and `Retry-After`.
- [x] Circuit breaker tripping on upstream failure and automatic half-open recovery.

