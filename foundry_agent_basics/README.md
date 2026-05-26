# Foundry Agent Basics — SOC Edition

Progressive notebooks that teach Microsoft Foundry agent development using
Security Operations Center (SOC) scenarios. Adapted from the
[MT-Foundry-Workshop](https://github.com/HaoZhang615/MT-Foundry-Workshop) with
all examples rewritten for cybersecurity / SOC use cases.

## Prerequisites

- Python 3.10+
- Azure CLI (`az login` completed)
- `workshop_config.json` in the repo root (created by `multi_agent/00-setup.ipynb`
  or `single_agent_skill/00-setup.ipynb`)

## Quick Start

1. Run `00-setup.ipynb` from either `multi_agent/` or `single_agent_skill/` to
   provision Azure resources and create `workshop_config.json`.
2. Install dependencies: `pip install -r requirements.txt`
3. Work through the notebooks in order: `01` → `02` → `03` → `04`.

## Notebooks

| Notebook | Duration | Topics |
|----------|----------|--------|
| `01-first-agent.ipynb` | ~8 min | First SOC Foundry agent, MCP grounding with Microsoft Learn, multi-turn conversations |
| `02-tools.ipynb` | ~10 min | Function calling (IP reputation), web search (threat intel), file search (SOC playbooks), code interpreter (alert analytics) |
| `03-prompts-eval.ipynb` | ~7 min | Basic vs. engineered prompts for alert triage, structured JSON verdicts, few-shot SOC advisor, multi-step investigation, evaluation |
| `04-orchestration.ipynb` | ~15 min | Sequential (triage pipeline), concurrent (parallel risk assessment), handoff (alert routing), group chat (SOC war room), custom QA workflow |

## Sample Data

| File | Description |
|------|-------------|
| `sample_data/soc_alert_spec.md` | SOC alert triage specification — alert types, severity SLAs, risk factors, PACO framework |
| `sample_data/soc_alerts_data.csv` | 20 synthetic SOC alerts for code interpreter analysis |
| `sample_data/eval_dataset.jsonl` | 6 SOC Q&A pairs for batch evaluation |

## Files

```
foundry_agent_basics/
├── 01-first-agent.ipynb       # Part 1: First SOC agent & MCP grounding
├── 02-tools.ipynb             # Part 2: IP lookup, web search, playbook RAG, alert analytics
├── 03-prompts-eval.ipynb      # Part 3: Prompt engineering for SOC & evaluation
├── 04-orchestration.ipynb     # Part 4: Multi-agent SOC orchestration patterns
├── link_checker.py            # URL validation utility (used by Investigation QA workflow)
├── requirements.txt           # Python dependencies
├── README.md                  # This file
└── sample_data/
    ├── soc_alert_spec.md      # SOC triage reference document (for file search/RAG)
    ├── soc_alerts_data.csv    # Alert dataset (for code interpreter)
    └── eval_dataset.jsonl     # Evaluation dataset (SOC Q&A pairs)
```

## SOC Concepts Covered

- **Impossible Travel Detection** — sign-ins from geographically distant locations
- **PACO Verdict Framework** — AccountCompromised, LikelyCompromised, Suspicious, BenignAnomaly, InsufficientData
- **MITRE ATT&CK Mapping** — T1078 (Valid Accounts), T1110 (Brute Force), T1621 (MFA Fatigue), T1528 (Steal Application Access Token)
- **Risk Factors** — location anomaly, authentication anomaly, IP reputation, MFA abuse, OAuth consent, mailbox manipulation
- **Microsoft Sentinel / Entra ID** — sign-in logs, audit logs, Identity Protection
