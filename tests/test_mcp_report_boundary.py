"""S-05: get_scan_report stays inside the workspace and targets must be http(s)."""

import os

import pytest

from suvari import mcp_server


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


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A cwd whose ``output`` directory holds one finished scan."""
    monkeypatch.chdir(tmp_path)
    scan = tmp_path / "output" / "scan-1"
    scan.mkdir(parents=True)
    (scan / "report.md").write_text("# findings\n")
    return tmp_path / "output"


@pytest.mark.parametrize("scan_dir", ["../../../etc", "/etc", "/etc/passwd"])
def test_get_scan_report_rejects_paths_outside_workspace(scan_dir):
    with pytest.raises(ValueError, match="outside the scan workspace"):
        mcp_server.get_scan_report(scan_dir)


def test_get_scan_report_rejects_sibling_with_root_as_name_prefix(workspace):
    sibling = workspace.parent / "output-private"
    sibling.mkdir()
    (sibling / "report.md").write_text("secret")
    with pytest.raises(ValueError):
        mcp_server.get_scan_report("../output-private")
    with pytest.raises(ValueError):
        mcp_server.get_scan_report(str(sibling))


def test_get_scan_report_reads_relative_scan(workspace):
    assert mcp_server.get_scan_report("scan-1") == "# findings\n"


def test_get_scan_report_reads_absolute_path_inside_workspace(workspace):
    assert mcp_server.get_scan_report(str(workspace / "scan-1")) == "# findings\n"


def test_get_scan_report_lists_scans(workspace):
    listing = mcp_server.get_scan_report()
    assert "Recent scans (1 total)" in listing
    assert "✓ scan-1" in listing


def test_get_scan_report_lists_nothing_without_workspace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert mcp_server.get_scan_report() == "No scans yet."


def test_get_scan_report_follows_patched_workspace_root(workspace, monkeypatch):
    monkeypatch.chdir(workspace.parent.parent)
    monkeypatch.setattr(mcp_server, "workspace_root", lambda: workspace)
    assert mcp_server.get_scan_report("scan-1") == "# findings\n"
    assert "scan-1" in mcp_server.get_scan_report()


def test_get_scan_report_missing_report(workspace):
    (workspace / "scan-2").mkdir()
    assert mcp_server.get_scan_report("scan-2") == "Report not found."


def test_get_scan_report_caps_output(workspace):
    (workspace / "scan-1" / "report.md").write_text("x" * 9000)
    assert len(mcp_server.get_scan_report("scan-1")) == 8000


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="requires os.symlink")
def test_get_scan_report_rejects_directory_symlink_leaving_workspace(workspace, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "report.md").write_text("secret")
    (workspace / "link").symlink_to(outside)
    with pytest.raises(ValueError):
        mcp_server.get_scan_report("link")


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="requires os.symlink")
def test_get_scan_report_rejects_report_symlink_leaving_workspace(workspace, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("secret")
    scan = workspace / "scan-3"
    scan.mkdir()
    (scan / "report.md").symlink_to(secret)
    with pytest.raises(ValueError):
        mcp_server.get_scan_report("scan-3")


@pytest.mark.parametrize(
    "target",
    [
        "file:///etc/hostname",
        "FILE:///etc/hostname",
        "gopher://x",
        " file:///etc/hostname",
        # curl accepts a scheme with no authority part, so these are schemes too
        "file:/etc/hostname",
        "file:etc/hostname",
        "dict:localhost:11211",
        "scp:/etc/hostname",
    ],
)
def test_validate_target_rejects_other_schemes(target):
    with pytest.raises(ValueError, match="target: scheme"):
        mcp_server.validate_target(target)


def test_validate_target_names_field_and_scheme():
    with pytest.raises(ValueError, match="url: scheme 'ftp'"):
        mcp_server.validate_target("ftp://x", field="url")


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1:8000/",
        "https://example.com",
        "HTTPS://example.com",
        "example.com",
        "example.com:8080",
        "",
    ],
)
def test_validate_target_allows_http_and_bare_hosts(target):
    assert mcp_server.validate_target(target) == target


def test_run_tool_rejects_file_scheme(stub_runner):
    with pytest.raises(ValueError):
        mcp_server.run_tool("curl", "file:///etc/hostname")
    assert stub_runner.calls == []


def test_registered_tool_rejects_file_scheme(stub_runner):
    with pytest.raises(ValueError):
        mcp_server._make_tool_fn("curl")("file:///etc/hostname")
    assert stub_runner.calls == []


def test_bad_target_rejected_when_tool_is_not_installed(stub_runner):
    with pytest.raises(ValueError):
        mcp_server.run_tool("nmap", "file:///etc/hostname")
    with pytest.raises(ValueError):
        mcp_server._make_tool_fn("nmap")("file:///etc/hostname")


def test_http_target_still_runs(stub_runner):
    assert "stub" in mcp_server.run_tool("curl", "http://127.0.0.1:8000/")
    assert "stub" in mcp_server._make_tool_fn("curl")("http://127.0.0.1:8000/")
    assert len(stub_runner.calls) == 2
