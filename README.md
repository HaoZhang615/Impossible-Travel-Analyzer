# Impossible Travel Analyzer

A demo repository that teaches Microsoft Foundry agent development and compares two ways to investigate Impossible Travel detections with the Microsoft Agent Framework and Microsoft Foundry.

The repo contains three sections:

- `foundry_agent_basics/`: **start here** — progressive notebooks that teach core Foundry agent concepts (tools, prompts, evaluation, orchestration) using SOC scenarios
- `multi_agent/`: fan-out and fan-in orchestration with 10 specialized risk-analysis agents and deterministic aggregation
- `single_agent_skill/`: a single agent that uses a file-based skill package with domain guidance and helper scripts

> **Recommended path:** If you are new to the Microsoft Agent Framework or Microsoft Foundry, work through `foundry_agent_basics/` first. It covers the building blocks (agents, function calling, prompt engineering, evaluation, and multi-agent orchestration) that the two investigation implementations build on.

The `multi_agent/` and `single_agent_skill/` folders implement the same SOC workflow against five synthetic detection scenarios and return a structured `InvestigationVerdict`.

## Sections

### Foundry Agent Basics (`foundry_agent_basics/`)

Progressive notebooks that teach Microsoft Foundry agent development using SOC scenarios. Adapted from the [MT-Foundry-Workshop](https://github.com/HaoZhang615/MT-Foundry-Workshop) with all examples rewritten for cybersecurity / SOC use cases.

| Notebook | Duration | Topics |
|----------|----------|--------|
| `01-first-agent.ipynb` | ~8 min | First SOC Foundry agent, MCP grounding with Microsoft Learn, multi-turn conversations |
| `02-tools.ipynb` | ~10 min | Function calling (IP reputation), web search (threat intel), file search (SOC playbooks), code interpreter (alert analytics) |
| `03-prompts-eval.ipynb` | ~7 min | Basic vs. engineered prompts for alert triage, structured JSON verdicts, few-shot SOC advisor, multi-step investigation, evaluation |
| `04-orchestration.ipynb` | ~15 min | Sequential (triage pipeline), concurrent (parallel risk assessment), handoff (alert routing), group chat (SOC war room), custom QA workflow |

### Investigation Approaches

| Topic | `multi_agent/` | `single_agent_skill/` |
|---|---|---|
| Core pattern | `WorkflowBuilder` fan-out and fan-in | One agent with file-based skill augmentation |
| Parallelism | Yes | No |
| Knowledge strategy | Specialized prompts per risk analyst | `skills/soc-impossible-travel/` with reference docs and scripts |
| Primary implementation | `investigation_workflow.py` | `single_agent_workflow.py` |
| Notebooks | `00-setup`, `01-investigation`, `02-deploy` | `00-setup`, `01-investigation`, `02-deploy` |
| Hosted deployment | Microsoft Foundry Hosted Agent | Microsoft Foundry Hosted Agent |

## Repository Layout

```text
.
├── README.md
├── workshop_config.json
├── foundry_agent_basics/
│   ├── 01-first-agent.ipynb
│   ├── 02-tools.ipynb
│   ├── 03-prompts-eval.ipynb
│   ├── 04-orchestration.ipynb
│   ├── requirements.txt
│   ├── sample_data/
│   └── README.md
├── multi_agent/
│   ├── 00-setup.ipynb
│   ├── 01-investigation.ipynb
│   ├── 02-deploy.ipynb
│   ├── investigation_workflow.py
│   ├── main.py
│   ├── hosted_agent/
│   ├── test_cases/
│   ├── eval_results/
│   └── README.md
├── single_agent_skill/
│   ├── 00-setup.ipynb
│   ├── 01-investigation.ipynb
│   ├── 02-deploy.ipynb
│   ├── single_agent_workflow.py
│   ├── tools.py
│   ├── subprocess_script_runner.py
│   ├── skills/
│   │   └── soc-impossible-travel/
│   │       ├── SKILL.md
│   │       ├── references/
│   │       └── scripts/
│   ├── hosted_agent/
│   ├── test_cases/
│   └── eval_results/
└── LICENSE
```

## Shared Test Scenarios

Both implementations use the same five cases:

| Case | Scenario | Expected verdict |
|---|---|---|
| 01 | Clear compromise with rapid geo-hop and suspicious follow-on activity | `true_positive` |
| 02 | Benign business travel | `benign` |
| 03 | MFA fatigue or push-bombing attack | `true_positive` |
| 04 | OAuth consent phishing | `true_positive` |
| 05 | Disabled-account sign-in attempt | `true_positive` |

## Prerequisites

- Python `3.13`
- Azure CLI with an active login
- A Microsoft Foundry project with a deployed chat model
- Docker Desktop running for hosted-agent deployment
- Access to the Azure resources referenced in `workshop_config.json`

### Local Tooling

- Install Python `3.13`.
- Install Azure CLI and authenticate with `az login` before running the notebooks.
- Install Docker Desktop if you plan to run `02-deploy.ipynb`.
- Install dependencies with either `uv` or `pip`:

```bash
# option 1: uv
uv add -r requirements.txt

# option 2: pip
pip install -r requirements.txt
```

Each implementation folder contains its own `requirements.txt`.

### Azure Access

- You need access to a Microsoft Foundry account and project.
- You need a deployed model referenced by `MODEL_DEPLOYMENT_NAME`.
- The notebooks authenticate with `AzureCliCredential`, so the active Azure CLI identity must be able to access the Foundry project and related Azure resources.

### Azure Roles For Deployment

If you only run `00-setup.ipynb` and `01-investigation.ipynb`, standard project access is usually enough. For `02-deploy.ipynb`, the signed-in Azure identity also needs permission to inspect resources and create role assignments.

The deployment notebooks ensure these roles for managed identities used by the Hosted Agent flow:

- `AcrPull` on the Azure Container Registry for the Foundry project managed identity
- `Cognitive Services OpenAI User` on the Foundry account for the agent runtime managed identity
- `Foundry User` on the Foundry account for the agent runtime managed identity
- `Monitoring Metrics Publisher` on Application Insights for the agent runtime managed identity

In practice, your signed-in user or service principal needs sufficient Azure RBAC to create those assignments during deployment, or those roles must already be in place.

The shared config file in the repo root contains:

- `RESOURCE_GROUP`
- `ACCOUNT_NAME`
- `PROJECT_NAME`
- `MODEL_DEPLOYMENT_NAME`
- `PROJECT_ENDPOINT`

## How To Run

### 1. Foundry Agent Basics (recommended first)

1. Run `00-setup.ipynb` from either `multi_agent/` or `single_agent_skill/` to provision Azure resources and create `workshop_config.json`.
2. `cd foundry_agent_basics && pip install -r requirements.txt`
3. Work through the notebooks in order: `01` → `02` → `03` → `04`.

### 2. Investigation implementations

Choose one implementation folder (multi_agent or single_agent_skill) and run the notebooks in order:

1. `00-setup.ipynb`
2. `01-investigation.ipynb`
3. `02-deploy.ipynb`

### Notebook Flow

| Notebook | Purpose |
|---|---|
| `00-setup.ipynb` | Install dependencies, validate credentials, and create or verify shared config |
| `01-investigation.ipynb` | Run the investigation workflow locally against the bundled test cases |
| `02-deploy.ipynb` | Package the implementation, build and push a container image, and register it as a Microsoft Foundry Hosted Agent |

The multi-agent variant has additional architecture notes in `multi_agent/README.md`. The single-agent variant is currently notebook-first and does not yet have its own local README.

## Outputs

Both variants return a structured `InvestigationVerdict` with:

- `verdict`
- `confidence`
- `reasoning`
- `actionPlan`
- `narrative`

The multi-agent implementation also produces intermediate structured evidence records during orchestration before the final verdict is generated.

## Notes

- Both `02-deploy.ipynb` notebooks target Microsoft Foundry Hosted Agents, not Azure Container Apps directly.
- The token usage cells in the deploy notebooks query Application Insights after invocation.
- The hosted containers bundle the same workflow code, skills, and test cases used during local execution.
