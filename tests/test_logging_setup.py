"""S-08: central logging setup, CLI flags, and logged (not silent) failures."""

import io
import logging
from pathlib import Path

import pytest
from typer.testing import CliRunner

from suvari import cli
from suvari.cli import app
from suvari.logging_setup import (
    LEVEL_NAMES,
    configure_logging,
    log_swallowed,
    parse_level,
)


# ── parse_level ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("value, expected", [
    ("critical", logging.CRITICAL),
    ("ERROR", logging.ERROR),
    ("Warning", logging.WARNING),
    ("warn", logging.WARNING),
    ("info", logging.INFO),
    ("DeBuG", logging.DEBUG),
])
def test_parse_level_accepts_names_case_insensitively(value, expected):
    assert parse_level(value) == expected


def test_parse_level_passes_ints_through():
    assert parse_level(logging.INFO) == logging.INFO


def test_parse_level_rejects_unknown_name_and_lists_allowed():
    with pytest.raises(ValueError) as exc_info:
        parse_level("bogus")
    for name in LEVEL_NAMES:
        assert name in str(exc_info.value)


# ── configure_logging ──────────────────────────────────────────────────────


def test_configure_logging_twice_leaves_one_root_handler():
    configure_logging("warning", stream=io.StringIO())
    configure_logging("warning", stream=io.StringIO())
    assert len(logging.getLogger().handlers) == 1


def test_configure_logging_sets_requested_level():
    configure_logging("INFO", stream=io.StringIO())
    assert logging.getLogger().level == logging.INFO


def test_configure_logging_debug_overrides_level():
    configure_logging("warning", debug=True, stream=io.StringIO())
    assert logging.getLogger().level == logging.DEBUG


def test_configure_logging_quiets_third_party_loggers():
    configure_logging("debug", stream=io.StringIO())
    assert logging.getLogger("httpx").level == logging.WARNING
    configure_logging("warning", debug=True, stream=io.StringIO())
    assert logging.getLogger("httpx").level == logging.INFO


def test_configure_logging_writes_formatted_lines_to_stream():
    stream = io.StringIO()
    configure_logging("info", stream=stream)
    logging.getLogger("suvari.test").info("hello")
    assert "INFO" in stream.getvalue()
    assert "suvari.test: hello" in stream.getvalue()


# ── log_swallowed ──────────────────────────────────────────────────────────


def test_log_swallowed_emits_warning_and_debug_traceback(caplog):
    logger = logging.getLogger("suvari.test")
    try:
        raise RuntimeError("disk on fire")
    except RuntimeError as e:
        with caplog.at_level(logging.DEBUG, logger="suvari.test"):
            log_swallowed(logger, "could not save %s", e, "report.md")

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    debugs = [r for r in caplog.records if r.levelno == logging.DEBUG]
    assert len(warnings) == 1
    assert "could not save report.md" in warnings[0].getMessage()
    assert "disk on fire" in warnings[0].getMessage()
    assert len(debugs) == 1
    assert debugs[0].exc_info is not None


# ── CLI ────────────────────────────────────────────────────────────────────


def test_cli_rejects_unknown_log_level():
    result = CliRunner().invoke(app, ["--log-level", "bogus", "scan", "http://x"])
    assert result.exit_code == 2
    for name in LEVEL_NAMES:
        assert name in result.output
    assert "Traceback" not in result.output


def test_cli_accepts_known_log_level():
    result = CliRunner().invoke(app, ["--log-level", "debug", "--help"])
    assert result.exit_code == 0
    assert "--log-level" in result.output


def test_write_last_pointer_writes_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "output").mkdir()
    assert cli._write_last_pointer(tmp_path / "scan-1") is True
    assert (tmp_path / "output" / ".last").read_text() == str(tmp_path / "scan-1")


def test_write_last_pointer_logs_failure(tmp_path, monkeypatch, caplog):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "output").mkdir()

    def boom(self, *args, **kwargs):
        raise OSError("read-only file system")

    monkeypatch.setattr(Path, "write_text", boom)
    with caplog.at_level(logging.WARNING, logger="suvari.cli"):
        assert cli._write_last_pointer(tmp_path / "scan-1") is False

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "read-only file system" in warnings[0].getMessage()
    assert not (tmp_path / "output" / ".last").exists()


# ── Orchestrator ───────────────────────────────────────────────────────────


def test_run_cve_intel_logs_instead_of_swallowing(monkeypatch, tmp_path, caplog):
    import suvari.cve_intel
    from suvari.orchestrator import SuvariOrchestrator

    def boom(_recon):
        raise RuntimeError("version parser exploded")

    monkeypatch.setattr(suvari.cve_intel, "extract_versions", boom)
    orch = object.__new__(SuvariOrchestrator)
    orch.context = {"recon_results": {}}
    orch.target_url = "http://x"

    with caplog.at_level(logging.WARNING, logger="suvari.orchestrator"):
        result = orch._run_cve_intel()

    assert result == []
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "version parser exploded" in warnings[0].getMessage()
