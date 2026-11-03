"""
Shell-free command pipelines.

Commands produced by the LLM (or derived from tool output) may contain a ``|``
to chain stages. Historically the whole string was handed to ``/bin/sh`` with
``shell=True``, which turned every ``;``, ``&&``, ``$(...)`` or backtick into
executable shell code — a live injection surface (see ANALIZ.md section 6).

This module instead tokenises the command with :mod:`shlex` and chains the
stages with :mod:`subprocess` pipes, so no shell is ever involved. Tokens that
are shell control/redirection operators, or that embed shell metacharacters,
are rejected rather than executed.
"""

import logging
import re
import subprocess
import time
from pathlib import Path
from typing import Optional

# Shared with tool argument validation; ``args`` must never import this module.
from .args import FORBIDDEN_SUBSTRINGS as _FORBIDDEN_SUBSTRINGS
from .args import OPERATOR_TOKENS as _OPERATOR_TOKENS

logger = logging.getLogger("suvari.pipeline")

# ANSI escape sequence cleaner. Defined here (not imported from ``runner``) so
# that ``runner`` can import it from this module without a circular import.
_ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def clean_ansi(text: str) -> str:
    """Remove ANSI escape sequences from tool output."""
    return _ANSI_RE.sub('', text)


class PipelineError(ValueError):
    """Raised when a command string cannot be executed without a shell."""


def split_pipeline(command: str) -> list[list[str]]:
    """Split ``command`` into pipeline stages of argv lists (no shell).

    The command is tokenised with :func:`shlex.split`; each bare ``|`` token
    separates stages. Shell control/redirection operators and tokens embedding
    shell metacharacters are rejected with :class:`PipelineError`.
    """
    import shlex

    if not command or not command.strip():
        raise PipelineError("empty command")

    try:
        tokens = shlex.split(command, comments=False, posix=True)
    except ValueError as e:
        raise PipelineError(f"could not parse command: {e}") from e

    stages: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token == "|":
            if not current:
                raise PipelineError("empty pipeline stage")
            stages.append(current)
            current = []
            continue
        if token in _OPERATOR_TOKENS:
            raise PipelineError(f"shell operator not allowed: {token}")
        for bad in _FORBIDDEN_SUBSTRINGS:
            if bad in token:
                raise PipelineError(f"shell metacharacter not allowed in token: {token}")
        current.append(token)

    if not current:
        raise PipelineError("empty pipeline stage")
    stages.append(current)

    for stage in stages:
        if not stage:
            raise PipelineError("empty pipeline stage")

    return stages


def run_pipeline(command: str, timeout: int = 120,
                 workdir: Optional[Path] = None) -> str:
    """Run ``command`` as a shell-free pipeline and return combined output.

    Stages are chained with :mod:`subprocess` pipes — never a shell. The output
    is the stdout of the last stage plus the stderr of every stage, with ANSI
    escape sequences removed. Callers apply their own length caps, so the result
    is not truncated here.
    """
    stages = split_pipeline(command)

    start = time.monotonic()
    stderr_parts: list[str] = []
    previous_stdout: Optional[str] = None

    for argv in stages:
        remaining = timeout - (time.monotonic() - start)
        if remaining <= 0:
            raise subprocess.TimeoutExpired(cmd=command, timeout=timeout)
        logger.debug("pipeline stage: %s", argv)
        try:
            result = subprocess.run(
                argv,
                input=previous_stdout,
                capture_output=True,
                text=True,
                timeout=remaining,
                cwd=workdir,
            )
        except subprocess.TimeoutExpired:
            raise subprocess.TimeoutExpired(cmd=command, timeout=timeout)
        except FileNotFoundError:
            return f"(tool not found: {argv[0]})"
        if result.stderr:
            stderr_parts.append(result.stderr)
        previous_stdout = result.stdout

    combined = (previous_stdout or "") + "".join(stderr_parts)
    combined = clean_ansi(combined).strip()
    return combined if combined else "(empty)"
