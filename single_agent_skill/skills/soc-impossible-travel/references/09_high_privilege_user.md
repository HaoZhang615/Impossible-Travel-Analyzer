# 09 — HighPrivilegeUser

**Tool:** `evaluate_high_privilege_user(upn)`

## What we evaluate

- Membership in **privileged roles**: Global Administrator, Exchange
  Administrator, Security Administrator, Privileged Role Administrator, User
  Administrator, Global Reader.
- Membership in **privileged groups**: `Executive-Access`, `Domain Admins`,
  `Enterprise Admins`.

This factor is **multiplicative**: it does not, on its own, indicate compromise
but it changes how PACO acts on every other risk:

- Mark every destructive action (`disableUserAccount`, `resetMfaMethods`,
  `revokeOAuthConsent`) with `requiresApproval: true`.
- Always add `escalateToTier2` to the action plan when score > 0.

## Scoring guidance

| Pattern                                                              | Band     |
|----------------------------------------------------------------------|----------|
| `is_high_privilege: false`                                           | 0        |
| One privileged group, no admin role                                  | 30–50    |
| One privileged admin role                                            | 60–80    |
| Multiple privileged roles or Global Administrator                    | 90–100   |

`Type`: `privileged_role`, `privileged_group`, `none`.
