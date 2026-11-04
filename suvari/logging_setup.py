"""
Central logging configuration for Suvari.

Every library module uses ``logging.getLogger("suvari.<module>")``; the CLI
and the MCP server call :func:`configure_logging` once at start-up.
"""

from __future__ import annotations

import logging
import sys
from typing import TextIO

LEVEL_NAMES = ("critical", "error", "warning", "info", "debug")
LEVEL_ALIASES = {"warn": "warning"}

LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"

# Third-party loggers that are chatty at INFO.
NOISY_LOGGERS = ("mcp", "httpx", "httpcore", "urllib3", "asyncio")


def parse_level(value: str | int) -> int:
    """Turn a level name (case-insensitive) or a numeric level into an int."""
    if isinstance(value, int):
        return value
    name = str(value).strip().lower()
    name = LEVEL_ALIASES.get(name, name)
    if name not in LEVEL_NAMES:
        raise ValueError(
            f"unknown log level {value!r}; choose one of: {', '.join(LEVEL_NAMES)}"
        )
    return getattr(logging, name.upper())


def configure_logging(level: str | int = "warning", *, debug: bool = False,
                      stream: TextIO | None = None) -> None:
    """Install a single root handler. Safe to call repeatedly."""
    resolved = logging.DEBUG if debug else parse_level(level)
    logging.basicConfig(
        level=resolved,
        format=LOG_FORMAT,
        stream=stream if stream is not None else sys.stderr,
        force=True,
    )
    noisy_level = logging.INFO if debug else logging.WARNING
    for name in NOISY_LOGGERS:
        logging.getLogger(name).setLevel(noisy_level)


def log_swallowed(logger: logging.Logger, message: str, exc: BaseException,
                  *args: object) -> None:
    """Record an exception that is deliberately not re-raised.

    Emits one WARNING with the message and ``str(exc)``, plus one DEBUG
    record carrying the traceback (visible with ``--debug``).
    """
    text = message % args if args else message
    logger.warning("%s: %s", text, exc)
    logger.debug("%s (traceback)", text, exc_info=exc)
