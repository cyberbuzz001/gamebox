"""Shared utility for safely running external security tools via subprocess.

All external tool invocations go through ``run_tool`` which enforces a
configurable timeout, captures stdout/stderr, and returns a structured
``ToolResult``. Modules should call ``tool_available`` first and degrade
gracefully when a tool is absent.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .logger import get_logger

log = get_logger("external")


@dataclass
class ToolResult:
    """Outcome of an external tool invocation."""

    command: str
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.error


def tool_available(name_or_path: str) -> bool:
    """Return True if *name_or_path* is an executable found on PATH or exists
    as a file."""
    if not name_or_path:
        return False
    if Path(name_or_path).is_file():
        return True
    return shutil.which(name_or_path) is not None


def run_tool(
    cmd: list[str],
    *,
    timeout: int = 30,
    cwd: str | None = None,
    stdin_data: str | None = None,
) -> ToolResult:
    """Execute *cmd* in a subprocess and return a :class:`ToolResult`.

    - *timeout* caps wall-clock time (seconds).
    - The process is killed on timeout; ``ToolResult.timed_out`` is set.
    - stdout and stderr are captured as UTF-8 text (decode errors replaced).
    """
    result = ToolResult(command=" ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            input=stdin_data,
            errors="replace",
        )
        result.returncode = proc.returncode
        result.stdout = proc.stdout
        result.stderr = proc.stderr
    except subprocess.TimeoutExpired:
        result.timed_out = True
        result.error = f"timed out after {timeout}s"
        log.warning("external tool timed out: %s", result.command)
    except FileNotFoundError:
        result.error = f"tool not found: {cmd[0]}"
        log.info("external tool not found: %s", cmd[0])
    except Exception as exc:
        result.error = str(exc)
        log.warning("external tool error: %s — %s", result.command, exc)
    return result
