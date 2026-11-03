"""S-07: tool argument strings are parsed with shlex and checked against deny/allow lists."""

import pytest

from suvari import mcp_server
from suvari.tools.args import ArgsError, parse_tool_args


class StubRunner:
    def __init__(self):
        self.calls = []

    def available_tools(self):
        return {"curl": "transfer a URL"}

    def run(self, cmd, timeout=120):
        self.calls.append(cmd)
        return "stub"


@pytest.fixture
def stub_runner(monkeypatch):
    stub = StubRunner()
    monkeypatch.setattr(mcp_server, "_get_runner", lambda: stub)
    return stub


@pytest.mark.parametrize("tool", ["curl", "customtool"])
@pytest.mark.parametrize("args", ["; rm -rf /", "$(id)", "a && id", "`id`", "x || id", "|"])
def test_shell_metacharacters_are_refused(tool, args):
    with pytest.raises(ArgsError):
        parse_tool_args(tool, args)


@pytest.mark.parametrize("tool", ["curl", "nmap", "sqlmap", "wget", "customtool"])
@pytest.mark.parametrize(
    ("args", "flag"),
    [
        ("-o /tmp/x", "-o"),
        ("-oN out.txt", "-oN"),
        ("--output=/tmp/x.html", "--output"),
        ("--os-shell", "--os-shell"),
        ("--os-pwn", "--os-pwn"),
    ],
)
def test_file_write_and_os_shell_flags_are_refused(tool, args, flag):
    with pytest.raises(ArgsError, match=flag):
        parse_tool_args(tool, args)


def test_legitimate_flags_pass():
    assert parse_tool_args("curl", "-s -S") == ["-s", "-S"]
    assert parse_tool_args("nmap", "-sV -Pn") == ["-sV", "-Pn"]
    assert parse_tool_args("sqlmap", "--batch --dbs") == ["--batch", "--dbs"]


def test_flag_outside_curated_allowlist_is_refused():
    with pytest.raises(ArgsError, match="--definitely-not"):
        parse_tool_args("nmap", "--definitely-not")
    assert parse_tool_args("customtool", "--definitely-not") == ["--definitely-not"]


def test_interpreter_tools_accept_no_flags():
    with pytest.raises(ArgsError, match="-c"):
        parse_tool_args("python3", "-c print(1)")
    assert parse_tool_args("python3", "") == []


@pytest.mark.parametrize("args", ["", "   ", "\t\n"])
def test_empty_input_returns_empty_list(args):
    assert parse_tool_args("curl", args) == []


def test_unbalanced_quotes_are_refused():
    with pytest.raises(ArgsError, match="could not parse args"):
        parse_tool_args("curl", '"unclosed')


def test_values_are_preserved():
    assert parse_tool_args("curl", "-H 'X-Test: 1' --max-time 5") == [
        "-H", "X-Test: 1", "--max-time", "5",
    ]


def test_quoted_pipe_inside_token_is_accepted():
    assert parse_tool_args("grep", '"a|b"') == ["a|b"]


def test_nmap_timing_template_is_not_the_denied_t_flag():
    assert parse_tool_args("nmap", "-T4 -p 80") == ["-T4", "-p", "80"]


def test_short_flags_that_only_write_files_for_one_tool():
    # nmap -O is OS detection and hydra -P is a password list: both are legitimate
    assert parse_tool_args("nmap", "-O -sV") == ["-O", "-sV"]
    assert parse_tool_args("hydra", "-P /usr/share/wordlists/rockyou.txt -l admin") == [
        "-P", "/usr/share/wordlists/rockyou.txt", "-l", "admin",
    ]
    # curl -O and wget -O/-P write files, so they stay refused for those tools
    with pytest.raises(ArgsError, match=r"flag -O is not allowed for curl"):
        parse_tool_args("curl", "-O http://example.com/x")
    with pytest.raises(ArgsError, match=r"flag -P is not allowed for wget"):
        parse_tool_args("wget", "-P /tmp http://example.com/x")


def test_run_tool_refuses_output_flag_without_running(stub_runner):
    result = mcp_server.run_tool("curl", "http://example.com", "-o /tmp/pwn.html")
    assert "error" in result
    assert "-o" in result
    assert stub_runner.calls == []


def test_dynamic_tool_refuses_output_flag_without_running(stub_runner):
    result = mcp_server._make_tool_fn("curl")("http://example.com", "-o /tmp/pwn.html")
    assert "error" in result
    assert "-o" in result
    assert stub_runner.calls == []


def test_dynamic_tool_runs_allowed_flags(stub_runner):
    mcp_server._make_tool_fn("curl")("http://example.com", "-s -S")
    assert len(stub_runner.calls) == 1
    argv = stub_runner.calls[0]
    assert "-s" in argv
    assert "-S" in argv
