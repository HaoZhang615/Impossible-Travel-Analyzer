"""Single-agent Impossible Travel investigator — Hosted Agent entrypoint.

Mirrors the deployment shape of the multi-agent project on ``main``: a thin
wrapper that:

  1. Reads platform-injected env vars (``FOUNDRY_PROJECT_ENDPOINT``,
     ``MODEL_DEPLOYMENT_NAME``).
  2. Hydrates the in-memory data sources from any ``test_cases/*.json``
     bundled into the container so the deployed agent can answer detections
     for the demo UPNs.
  3. Builds the single skill-driven agent and hosts it as an OpenAI
     Responses-compatible server.

Swap ``tools.py`` mocks for MCP calls to Sentinel / Entra / Defender XDR in
production — the agent and the ``soc-impossible-travel`` skill stay unchanged.
"""
from __future__ import annotations

import os
from pathlib import Path

from agent_framework.foundry import FoundryChatClient
from agent_framework_foundry_hosting import ResponsesHostServer
from azure.identity import DefaultAzureCredential

from single_agent_workflow import build_agent, load_test_cases_dir


def _configure_telemetry() -> None:
    """Disable OTEL sampling so every LLM span is exported to App Insights."""
    os.environ.setdefault("OTEL_TRACES_SAMPLER", "always_on")
    os.environ.setdefault("OTEL_BSP_MAX_QUEUE_SIZE", "4096")
    os.environ.setdefault("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "512")


def main() -> None:
    _configure_telemetry()
    project_endpoint = (
        os.environ.get("FOUNDRY_PROJECT_ENDPOINT")
        or os.environ["AZURE_AI_PROJECT_ENDPOINT"]
    )
    model_name = (
        os.environ.get("MODEL_DEPLOYMENT_NAME")
        or os.environ.get("AZURE_AI_MODEL_DEPLOYMENT_NAME", "gpt-4o")
    )

    here = Path(__file__).parent

    test_cases_dir = here / "test_cases"
    loaded = load_test_cases_dir(test_cases_dir)
    print(f"[startup] Loaded {loaded} test case(s) from {test_cases_dir}")

    skills_dir = here / "skills"

    credential = DefaultAzureCredential()
    client = FoundryChatClient(
        project_endpoint=project_endpoint,
        model=model_name,
        credential=credential,
    )

    store_threads = os.environ.get("WORKFLOW_STORE", "true").strip().lower() in (
        "1", "true", "yes", "on",
    )
    print(f"[startup] Workflow store={store_threads}")

    agent = build_agent(client, skills_dir=skills_dir, store=store_threads)
    server = ResponsesHostServer(agent)
    server.run()


if __name__ == "__main__":
    main()
