# PhishGuard AI - Dataset Provenance & Metadata

## Benchmark Information
- **Total Records:** 5,000
- **Phishing Samples:** 2,500 (Class 1)
- **Legitimate Samples:** 2,500 (Class 0)
- **Balance:** 50.0% / 50.0% Exact Stratified Distribution

## Data Sources
1. **Phishing Distribution:**
   - Source: Mitchell Krogza Phishing.Database (`phishing-links-ACTIVE.txt`)
   - Repository: `https://github.com/mitchellkrogza/Phishing.Database`
   - Licence: MIT Open Source License
   - Characteristics: Live and verified active phishing targets, banking impersonations, obfuscated subdomains, unencrypted forms, and IP hostnames.

2. **Legitimate Distribution:**
   - Source: Top Alexa / Tranco high-reputation domains across educational (.edu), governmental (.gov), global media, tech, and commerce.
   - Characteristics: Clean semantic directory structures, standard secure protocols (HTTPS), authentic query strings, and standard top-level domains.

## Target Encoding
- `0`: Legitimate URL
- `1`: Phishing URL
