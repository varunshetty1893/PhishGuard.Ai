# Threat Intelligence Data Privacy & Minimization Policy

PhishGuard AI takes strict precautions to safeguard user privacy when scanning web addresses.

## 1. Zero-Crawl Design
PhishGuard AI never visits, spiders, crawls, or opens an outbound HTTP session to the target destination during scanning. Scanning is conducted via offline deterministic lexical feature extraction and threat intelligence database lookups.

## 2. Third-Party Data Minimization
When external threat intelligence providers are contacted, only minimized data payloads are transmitted:

| Provider | Data Transmitted | Privacy Safeguard |
| :--- | :--- | :--- |
| **Google Safe Browsing v4** | Minimized URL (`scheme://host/path`) | All query strings, authentication parameters, tracking parameters, and fragment hashes (e.g. `?token=...#session`) are stripped prior to dispatch. |
| **PhishDestroy** | Destination Hostname only (e.g. `example.com`) | The entire path and query string are omitted. Only the hostname is checked against known threat domains. |
| **OpenPhish** | None (0 bytes outbound) | Operates entirely against an offline locally-cached feed. |
| **Phishing.Database** | None (0 bytes outbound) | Operates entirely against an offline locally-cached feed. |
| **CERT-PL** | None (0 bytes outbound) | Operates entirely against an offline locally-cached feed. |

## 3. Disabling Third-Party External Lookups
In high-privacy enterprise environments, all external third-party API lookups can be completely disabled by setting:

```env
ENABLE_THIRD_PARTY_LOOKUPS=false
```

When disabled:
- Neither Google Safe Browsing nor PhishDestroy will be contacted.
- They will return `Disabled by Policy` status.
- PhishGuard AI's machine learning model and offline local threat feeds (`OpenPhish`, `Phishing.Database`, `CERT-PL`) continue functioning with zero outbound network footprint.

