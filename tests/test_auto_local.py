"""Local audit against a fixture filesystem tree (nothing on the real host)."""

import os
import stat

import pytest

from suvari.auto.local import _decode_addr, run_local_audit
from suvari.auto.report import local_section


def _w(root, rel, text="", mode=None):
    p = root / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    if mode is not None:
        p.chmod(mode)
    return p


def _d(root, rel, mode):
    p = root / rel.lstrip("/")
    p.mkdir(parents=True, exist_ok=True)
    p.chmod(mode)
    return p


# 0.0.0.0:6379 and 127.0.0.1:5432 LISTEN, one ESTABLISHED (ignored)
PROC_NET_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 11111 1
   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 22222 1
   2: 0100007F:1538 0100007F:A000 01 00000000:00000000 00:00000000 00000000   999        0 33333 1
"""


@pytest.fixture()
def bad_host(tmp_path):
    root = tmp_path / "root"
    # alice must not be UID 0 even when the tests run as root
    uid = 1000 if os.getuid() == 0 else os.getuid()
    _w(root, "/etc/ssh/sshd_config",
       "# test\nInclude /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n"
       "Match User bob\n  PermitRootLogin no\n")
    _w(root, "/etc/ssh/sshd_config.d/10-root.conf",
       "PermitRootLogin yes\nPermitEmptyPasswords yes\n")
    _w(root, "/etc/passwd",
       "root:x:0:0:root:/root:/bin/bash\n"
       "toor:x:0:0::/root:/bin/sh\n"
       f"alice:x:{uid}:{uid}::/home/alice:/bin/bash\n"
       "nopass::1001:1001::/home/nopass:/bin/sh\n", mode=0o644)
    _w(root, "/etc/shadow", "root:$6$abc:19000::::::\nghost::19000::::::\n", mode=0o640)
    _w(root, "/etc/group", "docker:x:999:alice,bob\n")
    _w(root, "/etc/app.conf", "secret=1\n", mode=0o666)          # world-writable in /etc
    _d(root, "/tmp", 0o777)                                       # no sticky bit
    _d(root, "/var/www", 0o777)
    _w(root, "/var/run/docker.sock", "", mode=0o666)
    _w(root, "/etc/crontab", "* * * * * root /opt/backup.sh\n", mode=0o644)
    _w(root, "/opt/backup.sh", "#!/bin/sh\n", mode=0o777)        # script cron runs
    _d(root, "/etc/cron.d", 0o755)
    _w(root, "/etc/cron.d/job", "* * * * * root true\n", mode=0o666)
    find = _w(root, "/usr/bin/find", "", mode=0o755)
    find.chmod(0o4755)
    _w(root, "/usr/bin/passwd", "", mode=0o755).chmod(0o4755)
    _d(root, "/home/alice/.ssh", 0o777)
    _w(root, "/home/alice/.ssh/id_rsa", "KEY", mode=0o644)
    _w(root, "/home/alice/.ssh/id_rsa.pub", "PUB", mode=0o644)
    _w(root, "/home/alice/.ssh/authorized_keys", "ssh-ed25519 AAA", mode=0o666)
    _w(root, "/home/alice/.ssh/known_hosts", "", mode=0o666)
    if os.getuid() == 0:
        for p in [root / "home/alice/.ssh", *(root / "home/alice/.ssh").iterdir()]:
            os.chown(p, uid, uid)

    proc = tmp_path / "proc"
    _w(proc, "/net/tcp", PROC_NET_TCP)
    return root, proc


def _checks(audit):
    out = {}
    for f in audit.findings:
        out.setdefault(f.check, []).append(f)
    return out


def test_bad_host_findings(bad_host):
    root, proc = bad_host
    audit = run_local_audit(str(root), str(proc), use_tools=False)
    c = _checks(audit)

    # sshd: included file wins (first value), Match block ignored
    assert c["sshd-root-login"][0].severity == "HIGH"
    assert "PermitRootLogin yes" in c["sshd-root-login"][0].evidence
    assert c["sshd-password-auth"][0].severity == "MEDIUM"
    assert c["sshd-empty-passwords"][0].severity == "CRITICAL"

    # accounts
    assert [f.title for f in c["uid0"]] == ["Account toor has UID 0"]
    empty = {f.title for f in c["empty-password"]}
    assert "Account nopass has an empty password" in empty
    assert "Account ghost has an empty password" in empty

    # world-writable
    ww = {f.title for f in c["ww-dir"]}
    assert "/tmp is world-writable without the sticky bit" in ww
    assert "Critical directory /var/www is world-writable" in ww
    assert any(f.title == "World-writable file /etc/app.conf" for f in c["ww-file"])

    # docker
    assert c["docker-sock"][0].severity == "CRITICAL"
    assert "alice, bob" in c["docker-group"][0].evidence

    # cron: world-writable cron file and the script crontab runs
    cron = {f.title for f in c["cron-ww"]}
    assert "Cron file /etc/cron.d/job is world-writable" in cron
    assert "Script run by cron is world-writable: /opt/backup.sh" in cron

    # ~/.ssh
    assert "ssh-dir-perms" in c
    assert c["ssh-key-perms"][0].title == "Private key /home/alice/.ssh/id_rsa is readable by group/others"
    assert "ssh-authkeys-perms" in c
    assert "ssh-known-hosts-perms" in c
    assert "ssh-dir-owner" not in c  # owned by alice's uid

    # listeners: redis on 0.0.0.0 flagged, postgres on loopback not
    ports = {(l.address, l.port) for l in audit.listeners}
    assert ("0.0.0.0", 6379) in ports and ("127.0.0.1", 5432) in ports
    assert len(audit.listeners) == 2
    assert [f.title for f in c["listen-sensitive"]] == [
        "redis listening on all interfaces (0.0.0.0:6379)"]

    # suid: find counted; GTFOBins flag only meaningful when the file is root-owned
    assert audit.stats["suid"] == 2
    if os.getuid() == 0:
        assert c["suid-gtfo"][0].title.startswith("SUID-root /usr/bin/find")
    assert all("/usr/bin/passwd" not in f.title for f in audit.findings)

    # ids are sequential, sorted by severity, every finding has a fix
    assert [f.id for f in audit.findings] == [f"L{i:03d}" for i in range(1, len(audit.findings) + 1)]
    sev = [f.severity for f in audit.findings]
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    assert sev == sorted(sev, key=order.index)
    assert all(f.fix for f in audit.findings)


def test_hardened_host_is_quiet(tmp_path):
    root = tmp_path / "root"
    _w(root, "/etc/ssh/sshd_config",
       "PermitRootLogin prohibit-password\nPasswordAuthentication no\n")
    _w(root, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n", mode=0o644)
    _d(root, "/tmp", 0o1777)
    _d(root, "/root/.ssh", 0o700)
    _w(root, "/root/.ssh/authorized_keys", "k", mode=0o600)
    _w(root, "/root/.ssh/id_ed25519", "k", mode=0o600)
    proc = tmp_path / "proc"
    _w(proc, "/net/tcp", PROC_NET_TCP.splitlines()[0] + "\n")
    audit = run_local_audit(str(root), str(proc), use_tools=False)
    # only possible complaint: root's home dir ownership when tests do not run as root
    assert [f.check for f in audit.findings if f.check != "ssh-dir-owner"] == []


def test_password_auth_default_is_reported_as_default(tmp_path):
    root = tmp_path / "root"
    _w(root, "/etc/ssh/sshd_config", "Port 22\n")
    audit = run_local_audit(str(root), str(tmp_path / "proc"), use_tools=False)
    f = [x for x in audit.findings if x.check == "sshd-password-auth"][0]
    assert "OpenSSH default is yes" in f.evidence
    assert not [x for x in audit.findings if x.check == "sshd-root-login"]


def test_audit_never_modifies_the_tree(bad_host):
    root, proc = bad_host
    before = {p: (p.stat().st_mode, p.stat().st_mtime_ns)
              for p in root.rglob("*")}
    run_local_audit(str(root), str(proc), use_tools=False)
    after = {p: (p.stat().st_mode, p.stat().st_mtime_ns) for p in root.rglob("*")}
    assert before == after


def test_decode_proc_addresses():
    assert _decode_addr("0100007F:1F90", False) == ("127.0.0.1", 8080)
    assert _decode_addr("00000000000000000000000000000000:0016", True) == ("::", 22)
    assert _decode_addr("00000000000000000000000001000000:0050", True) == ("::1", 80)


def test_local_report_section(bad_host):
    root, proc = bad_host
    audit = run_local_audit(str(root), str(proc), use_tools=False).to_dict()
    text = "\n".join(local_section(audit))
    assert "## Local audit" in text
    assert "| L001 | CRITICAL |" in text
    assert "Listening sockets" in text


def test_local_only_job_without_targets(tmp_path, bad_host, monkeypatch):
    import json

    import suvari.auto.local as local_mod
    from suvari.auto.jobs import JobManager, JobRunner

    root, proc = bad_host
    fixture = run_local_audit(str(root), str(proc), use_tools=False)
    monkeypatch.setattr(local_mod, "run_local_audit", lambda *a, **k: fixture)
    mgr = JobManager(tmp_path / "jobs")
    job = mgr.create([], local=True, dry_run=True)
    assert job.targets == []
    result = JobRunner(job, mgr, handle_signals=False).run()
    assert result["status"] == "done"
    assert result["counters"]["local_findings"] == len(fixture.findings)
    jdir = tmp_path / "jobs" / job.id
    saved = json.loads((jdir / "local.json").read_text())
    assert len(saved["findings"]) == len(fixture.findings)
    report = (jdir / job.report).read_text()
    assert "## Local audit" in report and "local findings: " in report

    with pytest.raises(Exception):
        mgr.create([])  # no targets and no --local is still an error
