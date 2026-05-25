# 03 — TokenAnomaly

**Tool:** `evaluate_token_anomaly(upn)`

## What we evaluate

- **Concurrent sessions** — distinct `SessionId` values active at overlapping times.
- **Unusual token issuers** — anything other than `AzureAD`.
- **Non-interactive sign-in activity** following an interactive sign-in on the
  same IP (refresh-token replay indicator).
- Token reuse across geographically distant IPs.

## Scoring guidance

| Pattern                                                                                  | Band     |
|------------------------------------------------------------------------------------------|----------|
| Single session, AzureAD issuer, no non-interactive bursts                                | 0–10     |
| Concurrent sessions but all from same country/ASN                                        | 11–30    |
| Concurrent sessions across continents OR non-interactive Graph/Exchange calls from IoC IP| 50–70    |
| Non-AzureAD issuer **AND** concurrent geo-impossible sessions                            | 80–100   |

`Type`: `token_reuse`, `concurrent_sessions`, `refresh_token_replay`, `clean`.
