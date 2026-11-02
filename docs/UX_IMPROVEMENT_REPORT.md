# UX Improvement Report

## Overview
This document records the user-experience improvements made to PhishGuard AI during the Phase 6 frontend pass.

---

## Issues Addressed

### UX-01 — Off-Palette Orange Colour (#FF8C42)

| Field | Value |
|---|---|
| Severity | Low |
| File | `frontend/src/pages/ResultsPage.tsx` |
| Before | Three `#FF8C42` (orange) references used for "Suspicious" and partial-match risk indicators |
| After | Replaced with `#FFD54A` (neon-yellow), fully conforming to the product palette |

**Palette specification (enforced):**

| Colour | Hex | Meaning |
|---|---|---|
| Neon Green | `#39FF88` | Safe / Legitimate |
| Neon Yellow | `#FFD54A` | Suspicious / Warning |
| Red | `#FF525C` | Phishing / High Risk |
| Black | `#0D0D0D` | Background |

No blue, purple or orange shades appear anywhere in the production build after this change.

---

### UX-02 — `act(...)` Warning in Vitest (ScannerPage pre-fill test)

| Field | Value |
|---|---|
| Severity | Low |
| File | `frontend/src/__tests__/ScannerPage.test.tsx` |
| Before | State update for URL pre-fill was not wrapped in `waitFor()`, producing an `act(...)` console warning in every test run |
| After | Assertion wrapped in `await waitFor(...)`, warning eliminated |

Vitest result after fix: **33/33 passed, 0 warnings**.

---

### UX-03 — Five-Tier Result Labels (Verified Existing)

Inspection of `ResultsPage.tsx` (lines 112–136) confirmed the five-tier decision label system is already present and correctly implemented:

| Label | Trigger | Plain-language explanation shown |
|---|---|---|
| ✅ Safe | Score < 0.35 | "No threats detected by feeds or ML model" |
| ⚠️ Low Risk | 0.35 ≤ score < 0.50 | "Some minor risk indicators present" |
| 🔶 Suspicious | 0.50 ≤ score < 0.66 | "Multiple risk indicators detected, proceed with caution" |
| 🚨 Confirmed Phishing (known blocklist) | Feed match | "Found in known phishing or malware database" |
| ⚠️ Suspicious (unverified, ML only) | ML-only flag | "ML model flagged this URL — not in any blocklist" |

The last two labels enforce the honest-result requirement from Step 3 of the improvement brief: "Never show 'Phishing' for ML-only results."

---

## Frontend Test Health

| Suite | Tests | Result |
|---|---|---|
| `ScannerPage.test.tsx` | 12 | ✅ all pass |
| `ResultsPage.test.tsx` | 11 | ✅ all pass |
| `AnalyticsPage.test.tsx` | 10 | ✅ all pass |
| **Total** | **33** | **✅ 0 failures, 0 warnings** |

