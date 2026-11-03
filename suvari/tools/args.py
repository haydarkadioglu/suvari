"""
Validated tool argument parsing.

The argv of every MCP tool call is built from an ``args`` string supplied by an
LLM or a remote MCP client. It used to be split with ``str.split()`` and passed
straight to the tool, which let a caller write arbitrary files (``curl -o``,
``nmap -oN``) or open an OS shell on the target (``sqlmap --os-shell``) — see
ANALIZ.md sections 6 and 9.

This module tokenises the string with :mod:`shlex`, refuses shell operators and
metacharacters, refuses a deny list of dangerous flags for every tool, and
enforces a per-tool allow list of flags for the curated scanning tools.
"""

import logging
import shlex

logger = logging.getLogger("suvari.tools.args")


class ArgsError(ValueError):
    """Raised when a tool argument string is not allowed."""


# Tokens that are shell control/redirection operators on their own.
OPERATOR_TOKENS: frozenset[str] = frozenset({
    ";", "&", "&&", "||", ">", ">>", "<", "<<", "$", "(", ")", "{", "}",
})

# Substrings that reveal shell metacharacters inside a single token.
FORBIDDEN_SUBSTRINGS: tuple[str, ...] = (";", "`", "$(", "&&", "||")

# A bare ``|`` separates pipeline stages in ``pipeline``; in a tool argv it is
# never a legitimate value, so it is refused here on top of OPERATOR_TOKENS.
_ARGV_OPERATOR_TOKENS: frozenset[str] = OPERATOR_TOKENS | {"|"}

# Flags that are never allowed for any tool (file writes, code exec, OS shell).
DENIED_FLAGS: frozenset[str] = frozenset({
    # file writes
    "-o", "--output", "--output-file", "--output-dir",
    "-oN", "-oX", "-oG", "-oA", "-oJ", "-oH",
    "--directory-prefix", "-T", "--upload-file", "--write-file", "--log-file",
    # sqlmap OS takeover and file access
    "--os-shell", "--os-pwn", "--os-smbrelay", "--os-bof", "--os-cmd", "--os-args",
    "--file-write", "--file-dest", "--file-read",
    # code/script injection
    "--config", "--rc-file", "--eval", "--script",
})

# Flags that write a file for one tool only: ``-O`` is nmap's OS detection and
# ``-P`` is hydra's password list, so they cannot be denied globally.
DENIED_FLAGS_BY_TOOL: dict[str, frozenset[str]] = {
    "curl": frozenset({"-O"}),
    "wget": frozenset({"-O", "-P", "--output-document"}),
}

# Per-tool allowlist of flags including the leading dash. Tools without an
# entry are only checked against DENIED_FLAGS.
ALLOWED_FLAGS: dict[str, frozenset[str]] = {
    "curl": frozenset({
        "-s", "-S", "-L", "-I", "-i", "-k", "-v", "-H", "-A", "-X", "-d",
        "--silent", "--show-error", "--location", "--insecure", "--head",
        "--include", "--data", "--data-raw", "--user-agent", "--max-time",
        "--compressed", "--http1.1",
    }),
    "nmap": frozenset({
        "-sV", "-sS", "-sT", "-sU", "-sC", "-sn", "-Pn", "-p", "-A", "-O",
        "-v", "-n", "-F", "-T1", "-T2", "-T3", "-T4", "-T5", "--top-ports", "--open",
    }),
    "nuclei": frozenset({
        "-u", "-json", "-silent", "-severity", "-tags", "-t", "-rl", "-c", "-timeout",
    }),
    "sqlmap": frozenset({
        "-u", "--batch", "--dbs", "--tables", "--columns", "--dump", "--level",
        "--risk", "--dbms", "-p", "--technique", "--threads", "--random-agent",
    }),
    "nikto": frozenset({"-h", "-nointeractive", "-ssl", "-Tuning", "-Display", "-Format"}),
    "ffuf": frozenset({"-u", "-w", "-s", "-mc", "-fc", "-fs", "-H", "-X", "-d", "-t", "-rate"}),
    "gobuster": frozenset({"-u", "-w", "-q", "-t", "-x", "-r"}),
    "httpx": frozenset({
        "-u", "-l", "-silent", "-status-code", "-title", "-tech-detect", "-json",
        "-threads", "-timeout",
    }),
    "hydra": frozenset({"-l", "-L", "-p", "-P", "-t", "-f", "-s", "-u", "-vV"}),
    "whatweb": frozenset({"-a", "--url", "--no-errors", "-q"}),
    "wpscan": frozenset({"--url", "--no-update", "--enumerate", "--api-token", "--random-user-agent"}),
    "masscan": frozenset({"-p", "--rate", "--open-only", "-sS", "--wait"}),
    "dalfox": frozenset({"url", "--silence", "--deep-domxss", "-b", "--blind"}),
    # Interpreters accept no flags: -c / -e are code execution (re-opened by S-11).
    "python3": frozenset(),
    "python": frozenset(),
    "perl": frozenset(),
    "ruby": frozenset(),
    "sh": frozenset(),
    "bash": frozenset(),
}


def _refuse(message: str) -> ArgsError:
    logger.warning("tool args refused: %s", message)
    return ArgsError(message)


def parse_tool_args(tool: str, args: str) -> list[str]:
    """Split ``args`` into argv tokens and validate them for ``tool``.

    Raises :class:`ArgsError` for unparsable input, shell operators or
    metacharacters, denied flags, and flags outside the tool's allowlist.
    """
    if not args or not args.strip():
        return []

    try:
        tokens = shlex.split(args, comments=False, posix=True)
    except ValueError as e:
        raise _refuse(f"could not parse args: {e}") from e

    allowed = ALLOWED_FLAGS.get(tool)
    denied = DENIED_FLAGS | DENIED_FLAGS_BY_TOOL.get(tool, frozenset())
    for token in tokens:
        if token in _ARGV_OPERATOR_TOKENS:
            raise _refuse(f"shell operator not allowed: {token}")
        for bad in FORBIDDEN_SUBSTRINGS:
            if bad in token:
                raise _refuse(f"shell metacharacter not allowed in token: {token}")
        if token.startswith("-") and token != "-":
            flag = token.split("=", 1)[0]
            if flag in denied:
                raise _refuse(f"flag {flag} is not allowed for {tool}")
            if allowed is not None and flag not in allowed:
                raise _refuse(f"flag {flag} is not in the allowlist for {tool}")

    return tokens
