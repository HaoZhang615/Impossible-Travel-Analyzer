# 07 — OAuthAbuse

**Tool:** `evaluate_oauth_abuse(upn)`

## What we evaluate

- **Consent grants** to third-party applications (audit activity
  `Consent to application`).
- **High-privilege permissions** (any permission containing `Write` or
  `ReadWrite`, especially `Mail.ReadWrite`, `Files.ReadWrite.All`,
  `User.ReadWrite.All`, `offline_access` with broad scopes).
- **Unverified publisher** apps (where present in the audit record).
- Consent issued in close proximity to the suspicious sign-in.

## Scoring guidance

| Pattern                                                              | Band     |
|----------------------------------------------------------------------|----------|
| No consent grants in window                                          | 0–10     |
| Consent to verified, read-only app                                   | 11–30    |
| Consent with at least one Write/ReadWrite scope                      | 50–70    |
| Consent with mail/file ReadWrite + offline_access right after sign-in| 85–100   |

`Type`: `oauth_consent`, `oauth_persistence`, `none`. Note: OAuth backdoors
survive password resets — always include `revokeOAuthConsent` in the action
plan when this evidence is non-zero.
