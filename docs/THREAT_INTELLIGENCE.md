# PhishGuard AI — Threat Intelligence Integration Guide

## 1. Architectural Philosophy & Independence
PhishGuard AI enforces a strict architectural boundary between:
1. **Machine Learning Predictions:** Internal, offline lexical/structural classifier trained on URL features.
2. **External Threat Intelligence:** Authoritative external threat feeds queried via server-side REST APIs.
3. **Combined Assessment:** Transparent synthesis clearly communicating the evidence source.

> [!IMPORTANT]
> External Threat Intelligence providers are completely optional. PhishGuard AI operates with 100% functionality locally using the built-in Machine Learning engine if no API keys are configured.

---

## 2. Integrated Providers

### 2.1 Google Safe Browsing API v4
- **Official Documentation:** [Google Safe Browsing REST API v4](https://developers.google.com/safe-browsing/reference/rest)
- **Primary Focus:** Social engineering (Phishing), Malware, Unwanted Software.
- **Protocol:** Server-side HTTPS POST to `https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}`.
- **Environment Variable:** `GOOGLE_SAFE_BROWSING_API_KEY`.
- **Query Body Schema:**
```json
{
  "client": {
    "clientId": "phishguard-ai",
    "clientVersion": "1.0.0"
  },
  "threatInfo": {
    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
    "platformTypes": ["ANY_PLATFORM"],
    "threatEntryTypes": ["URL"],
    "threatEntries": [
      {"url": "https://example-suspect.com"}
    ]
  }
}
```
- **Response Parsing:**
  - If `matches` array is non-empty: Return `Threat Reported` with `threatType`.
  - If `matches` is absent/empty: Return `No Match Reported`.
  - On timeout / HTTP 4xx/5xx: Return `Unavailable`.
  - If API key is empty/unset: Return `Not Configured`.

---

### 2.2 Local phishing feeds
- **OpenPhish:** Exact URL matches against a periodically refreshed local public feed.
- **Phishing.Database:** URL and domain/subdomain matches against periodically refreshed local public lists.
- Feed refresh and cache state are reported separately; unavailable or empty data is not treated as a clean match.

### 2.3 PhishDestroy API
- Public domain and URL reputation lookups are performed server-side without an API key.

### 2.4 PhishStats API
- Exact URL verification supports anonymous access with a daily quota.
- **Environment Variable:** `PHISHSTATS_API_KEY` (optional; used for the higher quota).
- Quota errors and provider failures are reported as `Unavailable`, not as clean lookups.

---

## 3. Provider State Machine

```mermaid
stateDiagram-v2
    [*] --> CheckConfig : Scan Initiated
    CheckConfig --> NotConfigured : Key Missing / Disabled
    CheckConfig --> DispatchHTTP : Key Present / Public API Available
    
    DispatchHTTP --> TimeoutOrError : Network Failure / HTTP 5xx
    TimeoutOrError --> Unavailable
    
    DispatchHTTP --> ParseResponse : HTTP 200 OK
    ParseResponse --> ThreatReported : Threat Match Found
    ParseResponse --> NoMatchReported : Clean / No Records
    ParseResponse --> Inconclusive : Malformed Payload
    
    NotConfigured --> [*]
    Unavailable --> [*]
    ThreatReported --> [*]
    NoMatchReported --> [*]
    Inconclusive --> [*]
```

---

## 4. Synthesis & Grounding Rules
- **Rule 1 (No Invalidation of ML):** A `No Match Reported` from Safe Browsing does **not** make a URL safe. Attackers create thousands of zero-day phishing links per hour that have not yet been indexed by threat feeds. The ML classification reflects structural risk even when external feeds have no record yet.
- **Rule 2 (No Artificial Math Scores):** Never add or multiply ML probabilities with threat-intel flags into a meaningless "composite risk percentage".
- **Rule 3 (Safe Degradation):** Threat provider timeouts (configured at 4.0s) never block the ML response or abort the scan.
