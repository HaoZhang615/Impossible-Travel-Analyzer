# 08 — MailboxManipulation

**Tool:** `evaluate_mailbox_manipulation(upn)`

## What we evaluate

- **Inbox rules** created or modified.
- **External forwarding** — any rule whose `Actions.ForwardTo` resolves outside
  the tenant.
- **Delete-after-forward** — rules that forward then delete the source message
  (classic evidence-hiding pattern).
- **Rule name obfuscation** — single-character names, whitespace-only names,
  hidden Unicode.
- Related Defender alerts of type containing "inbox rule".

## Scoring guidance

| Pattern                                                              | Band     |
|----------------------------------------------------------------------|----------|
| No rules created in window                                           | 0–10     |
| Internal rule (e.g., move to folder), no external forward            | 11–30    |
| External forwarding rule                                             | 60–80    |
| External forward + delete-after-forward + obfuscated name            | 85–100   |

`Type`: `inbox_rule_exfil`, `internal_rule`, `none`. Action plan must include
`removeInboxRules` when score >0.
