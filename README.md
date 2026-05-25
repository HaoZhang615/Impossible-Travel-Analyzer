# Impossible Travel Analyzer

A demo project using the **Microsoft Agent Framework** to show two distinct architectural approaches for building a Security Operations Center (SOC) workflow that investigates *impossible travel* alerts.

Both approaches analyse the same 5 synthetic test cases and produce a structured `InvestigationVerdict` with a risk score, evidence chain, and recommended response actions.

---

## Approaches

| | [Multi-Agent Orchestration](multi_agent/) | [Single-Agent + Skill](single_agent_skill/) |
|---|---|---|
| **Architecture** | 10-agent fan-out / fan-in via `WorkflowBuilder` | 1 agent + file-based `AgentSkill` |
| **Parallelism** | Specialised sub-agents run concurrently | Sequential reasoning enriched by skill references & scripts |
| **Skill / Knowledge** | Each sub-agent has a narrowly scoped system prompt | `skills/soc-impossible-travel/` — SKILL.md, 13 reference docs, 3 helper scripts |
| **Entry point** | `investigation_workflow.py` | `single_agent_workflow.py` |
| **Notebooks** | `00-setup`, `01-investigation`, `02-deploy` | `00-setup`, `01-investigation`, `02-deploy` |
| **Test cases** | `test_cases/` (5 JSON files) | `test_cases/` (same 5 JSON files) |
| **Hosted agent** | `hosted_agent/` (FastAPI + Docker) | `hosted_agent/` (FastAPI + Docker) |

---

## Repository layout

```
.
├── multi_agent/          # Approach 1 — 10-agent WorkflowBuilder orchestration
│   ├── investigation_workflow.py
│   ├── main.py
│   ├── test_cases/
│   ├── hosted_agent/
│   ├── 00-setup.ipynb
│   ├── 01-investigation.ipynb
│   ├── 02-deploy.ipynb
│   └── README.md
│
├── single_agent_skill/   # Approach 2 — Single agent + file-based AgentSkill
│   ├── single_agent_workflow.py
│   ├── tools.py
│   ├── subprocess_script_runner.py
│   ├── skills/
│   │   └── soc-impossible-travel/
│   │       ├── SKILL.md
│   │       ├── references/   (13 markdown docs)
│   │       └── scripts/      (haversine, velocity, ip-reputation)
│   ├── test_cases/
│   ├── hosted_agent/
│   ├── eval_results/
│   ├── 00-setup.ipynb
│   ├── 01-investigation.ipynb
│   ├── 02-deploy.ipynb
│   └── README.md
│
└── LICENSE
```

---

## Getting started

Each approach is self-contained. Pick one, follow its `README.md`, and run the notebooks in order:

1. **`00-setup.ipynb`** — install dependencies, configure Azure credentials
2. **`01-investigation.ipynb`** — run investigations + batch eval against all 5 test cases
3. **`02-deploy.ipynb`** — containerise and deploy to Azure Container Apps

### Prerequisites

- Python 3.11+
- An Azure AI Foundry project (`AZURE_AI_PROJECT_CONNECTION_STRING`)
- A deployed chat-completion model (default: `gpt-4o`)
- Docker (for `02-deploy`)

---

## Background

The test cases cover five canonical impossible-travel scenarios:

| # | Scenario | Expected verdict |
|---|---|---|
| 01 | Clear account compromise (rapid geo-hop + lateral movement) | `true_positive` |
| 02 | Benign business travel (VPN + expected locations) | `benign` |
| 03 | MFA fatigue / push-bombing attack | `true_positive` |
| 04 | OAuth consent phishing (app grant abuse) | `true_positive` |
| 05 | Disabled-account sign-in attempt | `true_positive` |

Reference: *SOC — Impossible Travel: Multi-Agent Investigation Workflow* (see `multi_agent/` PDF).
