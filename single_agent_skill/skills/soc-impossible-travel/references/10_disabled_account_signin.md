# 10 — DisabledAccountSignIn

**Tool:** `evaluate_disabled_account_signin(upn)`

## What we evaluate

- `AccountEnabled` flag from the Entra profile.
- Any **successful sign-in** observations after the account was disabled
  (typically via cached refresh-token replay or persistent device tokens).
- `RiskState` from Entra ID Protection.

## Scoring guidance

| Pattern                                                                | Band     |
|------------------------------------------------------------------------|----------|
| Account enabled, no anomaly                                            | 0        |
| Account enabled but `RiskState != none`                                | 20–40    |
| Account disabled but no successful sign-ins in window                  | 30–50    |
| Account disabled **AND** successful sign-ins observed                  | 90–100   |

`Type`: `disabled_signin`, `risky_state`, `none`. When score >=90 the verdict
must be `AccountCompromised` with `High` confidence and `disableUserAccount` +
`revokeUserSessions` must appear in the action plan.
