"""Tests for shell-free command pipelines in ``suvari.tools.pipeline``.

These confirm that command strings are tokenised and chained without a shell:
real pipelines work, injection payloads are rejected rather than executed, and
the :class:`ToolRunner` wrapper applies its usual caching policy.
"""

import pytest


class TestSplitPipeline:
    """Shell-free parsing of command strings into argv stages."""

    def test_simple_pipeline(self):
        from suvari.tools.pipeline import split_pipeline
        assert split_pipeline("ls | wc -l") == [["ls"], ["wc", "-l"]]

    def test_quoted_pipe_is_not_a_stage_separator(self):
        from suvari.tools.pipeline import split_pipeline
        assert split_pipeline("echo 'a|b'") == [["echo", "a|b"]]

    def test_whitespace_only_raises(self):
        from suvari.tools.pipeline import PipelineError, split_pipeline
        with pytest.raises(PipelineError):
            split_pipeline("  ")

    def test_trailing_pipe_raises(self):
        from suvari.tools.pipeline import PipelineError, split_pipeline
        with pytest.raises(PipelineError):
            split_pipeline("ls |")

    def test_double_pipe_raises(self):
        from suvari.tools.pipeline import PipelineError, split_pipeline
        with pytest.raises(PipelineError):
            split_pipeline("ls || wc")

    @pytest.mark.parametrize("payload", [
        "ls; id",
        "ls && id",
        "ls $(id)",
        "ls `id`",
        "ls > /tmp/x",
        "ls & id",
    ])
    def test_shell_operators_rejected(self, payload):
        from suvari.tools.pipeline import PipelineError, split_pipeline
        with pytest.raises(PipelineError):
            split_pipeline(payload)


class TestInjectionNotExecuted:
    """Injection payloads must never run as shell code."""

    @pytest.mark.parametrize("template", [
        "ls; touch {marker}",
        "ls && touch {marker}",
        "ls $(touch {marker})",
        "ls `touch {marker}`",
        "echo hi; touch {marker}",
        "echo hi && touch {marker}",
    ])
    def test_marker_not_created(self, tmp_path, template):
        from suvari.tools.runner import ToolRunner
        marker = tmp_path / "pwned"
        payload = template.format(marker=marker)
        ToolRunner().run_pipeline(payload)
        assert not marker.exists()


class TestRunPipeline:
    """Real pipelines execute without a shell."""

    def test_sort_pipeline(self):
        from suvari.tools.pipeline import run_pipeline
        out = run_pipeline("printf 'b\\na\\n' | sort")
        assert out.splitlines() == ["a", "b"]

    def test_wc_byte_count(self):
        from suvari.tools.pipeline import run_pipeline
        assert "1" in run_pipeline("printf 'x' | wc -c")

    def test_missing_tool_returns_message(self):
        from suvari.tools.pipeline import run_pipeline
        out = run_pipeline("definitely-not-a-tool-xyz | wc -l")
        assert "tool not found" in out


class TestToolRunnerPipeline:
    """The ToolRunner wrapper caches and guards pipeline runs."""

    def test_cached_second_call(self):
        from suvari.tools.runner import ToolRunner
        runner = ToolRunner()
        first = runner.run_pipeline("printf 'a\\nb\\n' | sort")
        second = runner.run_pipeline("printf 'a\\nb\\n' | sort")
        assert first == second
        assert len(runner._cache) >= 1

    def test_injection_returns_error(self):
        from suvari.tools.runner import ToolRunner
        out = ToolRunner().run_pipeline("echo hi; id")
        assert out.startswith("(error:")
