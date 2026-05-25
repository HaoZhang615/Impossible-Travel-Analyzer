# 02 — AuthenticationAnomaly

**Tool:** `evaluate_authentication_anomaly(upn)`

## What we evaluate

- Deviation from the user's normal auth method (`Password+MFA`).
- Sessions where MFA was **bypassed** (`Password` only, `Token` only, etc.).
- Sign-ins from **non-compliant devices** (`DeviceCompliant: false`).
- Mixed-method bursts within a short window (e.g., MFA then plain password from
  another IP).

## Scoring guidance

| Pattern                                                                   | Band     |
|---------------------------------------------------------------------------|----------|
| All sessions use Password+MFA, all devices compliant                      | 0–10     |
| One off-policy session from a known/trusted location                      | 11–30    |
| MFA bypass on at least one session **OR** non-compliant device on IoC IP  | 50–70    |
| MFA bypass **AND** non-compliant device **AND** IoC IP overlap            | 80–100   |

`Type`: `auth_deviation`, `mfa_bypass`, `compliant_only`. `Value`: which method
was used and from which IP. `Reason`: tie the deviation to the IoC IPs where
possible.
