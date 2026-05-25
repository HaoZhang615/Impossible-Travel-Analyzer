# 05 — MfaAbuse

**Tool:** `evaluate_mfa_abuse(upn)`

## What we evaluate

- **MFA method changes** in the audit log — new phone, new authenticator app,
  TAP issuance, FIDO key registration.
- **MFA push fatigue** — many `MFA prompt sent` events in quick succession
  followed by a single approval (often visible in security alerts of type
  "Multi-factor authentication fraud attempt").
- **Changes made shortly after** a suspicious sign-in (attacker persistence).

## Scoring guidance

| Pattern                                                                  | Band     |
|--------------------------------------------------------------------------|----------|
| No MFA changes                                                           | 0–10     |
| Routine method addition outside the detection window                     | 11–30    |
| MFA method added or changed during/after the detection window            | 60–80    |
| Push-bombing alert AND eventual approval AND method swap                 | 85–100   |

`Type`: `mfa_method_change`, `push_bombing`, `none`.
