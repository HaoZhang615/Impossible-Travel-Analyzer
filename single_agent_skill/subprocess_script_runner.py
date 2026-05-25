# Copyright (c) Microsoft. All rights reserved.
# Vendored from python/samples/02-agents/skills/subprocess_script_runner.py in the
# microsoft/agent-framework repository (MIT licensed).

"""Sample subprocess-based skill script runner.

Executes file-based skill scripts as local Python subprocesses.
This is provided for demonstration purposes only.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

from agent_framework import FileSkill, FileSkillScript


def subprocess_script_runner(
    skill: FileSkill, script: FileSkillScript, args: dict[str, Any] | list[str] | None = None
) -> str:
    """Run a skill script as a local Python subprocess."""
    script_path = Path(script.full_path)
    if not script_path.is_file():
        return f"Error: Script file not found: {script_path}"
    cmd = [sys.executable, str(script_path)]
    if isinstance(args, list):
        for item in args:
            if not isinstance(item, str):
                raise TypeError(
                    f"File-based skill scripts only accept string CLI arguments "
                    f"but received a {type(item).__name__}. "
                    f"All array elements must be strings."
                )
        cmd.extend(args)
    elif args is not None:
        raise TypeError(
            f"Expected a list of CLI arguments but received {type(args).__name__}. "
            f"File-based skill scripts expect positional arguments as a list of strings."
        )
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(script_path.parent),
        )
        output = result.stdout
        if result.stderr:
            output += f"\nStderr:\n{result.stderr}"
        if result.returncode != 0:
            output += f"\nScript exited with code {result.returncode}"
        return output.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return f"Error: Script '{script.name}' timed out after 30 seconds."
    except OSError as e:
        return f"Error: Failed to execute script '{script.name}': {e}"
