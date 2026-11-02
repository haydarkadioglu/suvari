"""
Read-only security audit of the machine Suvari runs on (``--local``).

Nothing is changed, executed (except the optional, read-only ``sshd -T``) or
sent over the network. Every path is resolved under ``root`` (default ``/``)
and every ``/proc`` read under ``proc``, so the audit can be pointed at a
fixture tree in tests.

Checks:
  * listening sockets (``/proc/net/{tcp,tcp6,udp,udp6}``) with socket -> process
    mapping; sensitive services bound to all interfaces are findings
  * ``sshd_config`` (+ ``Include``): PermitRootLogin, PasswordAuthentication,
    PermitEmptyPasswords
  * world-writable critical directories/files (``/etc``, ``/var/www``, ``/tmp``
    without sticky bit, ...)
  * SUID/SGID binaries: count, plus the unusual and the GTFOBins-known ones
  * ``docker.sock`` permissions and docker group members
  * cron: world-writable cron files/dirs and scripts they run
  * ``~/.ssh`` permissions, ``authorized_keys`` ownership, private key and
    ``known_hosts`` permissions
  * ``/etc/passwd``/``/etc/shadow``: extra UID 0 accounts, empty passwords,
    file permissions
"""

from __future__ import annotations

import glob
import os
import re
import shutil
import socket
import stat
import struct
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class LocalFinding:
    id: str
    severity: str
    title: str
    evidence: str
    fix: str
    check: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Listener:
    proto: str
    address: str
    port: int
    process: str = ""
    pid: Optional[int] = None

    @property
    def wildcard(self) -> bool:
        return self.address in ("0.0.0.0", "::", "*")

    @property
    def loopback(self) -> bool:
        return self.address.startswith("127.") or self.address == "::1"


@dataclass
class LocalAudit:
    findings: list[LocalFinding] = field(default_factory=list)
    listeners: list[Listener] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"findings": [f.to_dict() for f in self.findings],
                "listeners": [asdict(l) for l in self.listeners],
                "stats": self.stats, "notes": self.notes}

    @classmethod
    def from_dict(cls, d: dict) -> "LocalAudit":
        return cls(findings=[LocalFinding(**f) for f in d.get("findings", [])],
                   listeners=[Listener(**l) for l in d.get("listeners", [])],
                   stats=d.get("stats", {}), notes=d.get("notes", []))


# Services that should never listen on all interfaces of a server by default.
SENSITIVE_PORTS = {
    2375: "docker-api", 2376: "docker-api", 3306: "mysql", 5432: "postgres",
    5984: "couchdb", 6379: "redis", 9200: "elasticsearch", 9300: "elasticsearch",
    11211: "memcached", 27017: "mongodb", 27018: "mongodb", 5900: "vnc",
    1433: "mssql", 2379: "etcd", 8086: "influxdb", 15672: "rabbitmq-mgmt",
    5672: "amqp", 9042: "cassandra", 10250: "kubelet",
}

# SUID binaries that give a shell / file read-write if set-uid (GTFOBins).
GTFO_SUID = {
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "find", "vim", "vi", "nano",
    "less", "more", "awk", "gawk", "mawk", "nmap", "python", "python2", "python3",
    "perl", "ruby", "lua", "php", "node", "env", "cp", "mv", "tar", "zip", "unzip",
    "rsync", "tee", "dd", "xxd", "base64", "busybox", "docker", "socat", "nc",
    "netcat", "wget", "curl", "gdb", "strace", "taskset", "nice", "time",
    "timeout", "stdbuf", "ionice", "systemctl", "openssl", "git", "make", "ed",
    "sed", "cat", "head", "tail", "od", "hexdump", "chmod", "chown", "ln",
}
# SUID binaries that are normal on Linux distributions.
EXPECTED_SUID = {
    "su", "sudo", "passwd", "chsh", "chfn", "gpasswd", "newgrp", "mount", "umount",
    "pkexec", "fusermount", "fusermount3", "ping", "ping6", "traceroute6.iputils",
    "ssh-keysign", "dbus-daemon-launch-helper", "polkit-agent-helper-1",
    "chrome-sandbox", "Xorg.wrap", "ntfs-3g", "unix_chkpwd", "pam_extrausers_chkpwd",
    "expiry", "chage", "crontab", "ssh-agent", "wall", "write", "bsd-write",
    "at", "newuidmap", "newgidmap", "snap-confine", "sg", "staprun", "mount.nfs",
    "mount.cifs", "dmcrypt-get-device", "lxc-user-nic", "vmware-user-suid-wrapper",
    "doas", "sudo.ws", "sudo-rs", "plocate", "mlocate", "utempter", "Xorg", "ksu", "uuidd",
}
SUID_DIRS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin",
             "/usr/local/sbin", "/usr/lib", "/usr/libexec", "/opt", "/snap/bin")
SUID_SCAN_CAP = 200_000


class _Auditor:
    def __init__(self, root: str = "/", proc: str = "/proc",
                 use_tools: Optional[bool] = None, home_dirs: Optional[list[str]] = None):
        self.root = Path(root)
        self.proc = Path(proc)
        # external helpers (sshd -T, ss) only make sense against the real system
        self.use_tools = (str(root) == "/") if use_tools is None else use_tools
        self.home_dirs = home_dirs
        self.audit = LocalAudit()

    # ── helpers ─────────────────────────────────────────────────────────
    def p(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def rel(self, path: Path) -> str:
        try:
            return "/" + str(Path(path).relative_to(self.root)).lstrip("/")
        except ValueError:
            return str(path)

    def add(self, check: str, severity: str, title: str, evidence: str, fix: str) -> None:
        self.audit.findings.append(LocalFinding(
            id="", severity=severity, title=title, evidence=evidence, fix=fix, check=check))

    def lstat(self, path: Path) -> Optional[os.stat_result]:
        try:
            return path.lstat()
        except OSError:
            return None

    def read(self, path: Path) -> Optional[str]:
        try:
            return path.read_text(errors="replace")
        except OSError:
            return None

    # ── run ─────────────────────────────────────────────────────────────
    def run(self) -> LocalAudit:
        for fn in (self.listening, self.sshd, self.world_writable, self.suid,
                   self.docker, self.cron, self.accounts, self.ssh_dirs):
            try:
                fn()
            except Exception as e:  # noqa: BLE001 - one check must not end the audit
                self.audit.notes.append(f"{fn.__name__} failed: {e}")
        self.audit.findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.check, f.title))
        for i, f in enumerate(self.audit.findings, 1):
            f.id = f"L{i:03d}"
        return self.audit

    # ── listening sockets ───────────────────────────────────────────────
    def listening(self) -> None:
        inode_proc = self._socket_inodes()
        listeners: list[Listener] = []
        for proto, fname, v6 in (("tcp", "tcp", False), ("tcp", "tcp6", True),
                                 ("udp", "udp", False), ("udp", "udp6", True)):
            text = self.read(self.proc / "net" / fname)
            if text is None:
                continue
            for line in text.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 10:
                    continue
                st = parts[3]
                if (proto == "tcp" and st != "0A") or (proto == "udp" and st != "07"):
                    continue
                addr, port = _decode_addr(parts[1], v6)
                inode = parts[9]
                pid, name = inode_proc.get(inode, (None, ""))
                listeners.append(Listener(proto, addr, port, name, pid))
        uniq = {(l.proto, l.address, l.port): l for l in listeners}
        self.audit.listeners = sorted(uniq.values(), key=lambda l: (l.proto, l.port, l.address))
        self.audit.stats["listeners"] = len(self.audit.listeners)
        if not inode_proc and self.audit.listeners:
            self.audit.notes.append("socket->process mapping unavailable (needs root)")
        seen = set()
        for l in self.audit.listeners:
            svc = SENSITIVE_PORTS.get(l.port)
            if l.proto == "tcp" and svc and l.wildcard and (l.port, svc) not in seen:
                seen.add((l.port, svc))
                self.add("listen-sensitive", "MEDIUM",
                         f"{svc} listening on all interfaces ({l.address}:{l.port})",
                         f"{l.proto} {l.address}:{l.port}"
                         + (f" process={l.process} pid={l.pid}" if l.process else ""),
                         f"Bind {svc} to 127.0.0.1 or a private interface, or firewall "
                         f"port {l.port}.")

    def _socket_inodes(self) -> dict[str, tuple[int, str]]:
        out: dict[str, tuple[int, str]] = {}
        for pid_dir in glob.glob(str(self.proc / "[0-9]*")):
            pid = int(os.path.basename(pid_dir))
            try:
                fds = os.listdir(f"{pid_dir}/fd")
            except OSError:
                continue
            name = ""
            for fd in fds:
                try:
                    target = os.readlink(f"{pid_dir}/fd/{fd}")
                except OSError:
                    continue
                m = re.match(r"socket:\[(\d+)\]", target)
                if m:
                    if not name:
                        name = (self.read(Path(pid_dir) / "comm") or "?").strip()
                    out.setdefault(m.group(1), (pid, name))
        return out

    # ── sshd ────────────────────────────────────────────────────────────
    def sshd(self) -> None:
        cfg_path = self.p("/etc/ssh/sshd_config")
        effective: dict[str, str] = {}
        source = ""
        if self.use_tools and shutil.which("sshd"):
            try:
                proc = subprocess.run(["sshd", "-T"], capture_output=True, text=True,
                                      timeout=5, shell=False)
                if proc.returncode == 0:
                    for line in proc.stdout.splitlines():
                        k, _, v = line.partition(" ")
                        effective.setdefault(k.lower(), v.strip().lower())
                    source = "sshd -T (effective config)"
            except (OSError, subprocess.SubprocessError):
                pass
        if not effective:
            if not cfg_path.exists():
                self.audit.notes.append("sshd_config not found; SSH checks skipped")
                return
            effective = self._parse_sshd(cfg_path, set())
            source = self.rel(cfg_path)
        self.audit.stats["sshd_source"] = source

        def val(key: str, default: str) -> tuple[str, bool]:
            return (effective[key], True) if key in effective else (default, False)

        prl, explicit = val("permitrootlogin", "prohibit-password")
        if prl == "yes":
            self.add("sshd-root-login", "HIGH", "SSH permits root login with a password",
                     f"PermitRootLogin {prl} ({source})",
                     "Set `PermitRootLogin prohibit-password` (or `no`) and reload sshd.")
        pa, explicit = val("passwordauthentication", "yes")
        if pa == "yes":
            self.add("sshd-password-auth", "MEDIUM", "SSH password authentication enabled",
                     f"PasswordAuthentication {pa}"
                     + ("" if explicit else " (not set; OpenSSH default is yes)")
                     + f" ({source})",
                     "Use key-based authentication and set `PasswordAuthentication no`.")
        pe, _ = val("permitemptypasswords", "no")
        if pe == "yes":
            self.add("sshd-empty-passwords", "CRITICAL", "SSH permits empty passwords",
                     f"PermitEmptyPasswords {pe} ({source})",
                     "Set `PermitEmptyPasswords no`.")

    def _parse_sshd(self, path: Path, seen: set) -> dict[str, str]:
        """First value wins (sshd semantics); stops at the first ``Match``."""
        out: dict[str, str] = {}
        if path in seen:
            return out
        seen.add(path)
        text = self.read(path) or ""
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = re.split(r"[\s=]+", line, maxsplit=1)
            key = parts[0].lower()
            val = parts[1].strip().lower() if len(parts) > 1 else ""
            if key == "match":
                break
            if key == "include":
                for pat in val.split():
                    pat = pat if pat.startswith("/") else f"/etc/ssh/{pat}"
                    for inc in sorted(glob.glob(str(self.p(pat)))):
                        for k, v in self._parse_sshd(Path(inc), seen).items():
                            out.setdefault(k, v)
                continue
            out.setdefault(key, val)
        return out

    # ── world-writable ──────────────────────────────────────────────────
    def world_writable(self) -> None:
        for d in ("/tmp", "/var/tmp", "/dev/shm"):
            st = self.lstat(self.p(d))
            if st and stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_IWOTH \
                    and not st.st_mode & stat.S_ISVTX:
                self.add("ww-dir", "HIGH", f"{d} is world-writable without the sticky bit",
                         f"{d} mode {stat.filemode(st.st_mode)}",
                         f"chmod 1777 {d}")
        for d in ("/etc", "/etc/ssh", "/etc/sudoers.d", "/etc/systemd/system",
                  "/etc/init.d", "/usr/local/bin", "/usr/local/sbin", "/usr/bin",
                  "/root", "/var/www", "/opt"):
            st = self.lstat(self.p(d))
            if st and stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_IWOTH:
                self.add("ww-dir", "HIGH", f"Critical directory {d} is world-writable",
                         f"{d} mode {stat.filemode(st.st_mode)}", f"chmod o-w {d}")
        found = self._ww_files(("/etc", "/var/www"), limit=20, max_files=50_000)
        for path, mode in found:
            sev = "HIGH" if path.startswith("/etc") else "MEDIUM"
            self.add("ww-file", sev, f"World-writable file {path}",
                     f"{path} mode {stat.filemode(mode)}", f"chmod o-w {path}")
        self.audit.stats["world_writable_files"] = len(found)

    def _ww_files(self, roots: Iterable[str], limit: int, max_files: int) -> list[tuple[str, int]]:
        out: list[tuple[str, int]] = []
        seen_files = 0
        for r in roots:
            base = self.p(r)
            if not base.is_dir():
                continue
            for dirpath, dirnames, filenames in os.walk(base):
                for name in dirnames + filenames:
                    seen_files += 1
                    full = Path(dirpath) / name
                    st = self.lstat(full)
                    if st is None or stat.S_ISLNK(st.st_mode):
                        continue
                    if st.st_mode & stat.S_IWOTH and not (
                            stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX):
                        out.append((self.rel(full), st.st_mode))
                        if len(out) >= limit:
                            return out
                if seen_files > max_files:
                    self.audit.notes.append(f"world-writable scan of {r} capped at {max_files} entries")
                    break
        return out

    # ── SUID / SGID ─────────────────────────────────────────────────────
    def suid(self) -> None:
        suid, sgid, scanned = [], [], 0
        for d in SUID_DIRS:
            base = self.p(d)
            if not base.is_dir():
                continue
            for dirpath, dirnames, filenames in os.walk(base):
                for name in filenames:
                    scanned += 1
                    full = Path(dirpath) / name
                    st = self.lstat(full)
                    if st is None or not stat.S_ISREG(st.st_mode):
                        continue
                    if st.st_mode & stat.S_ISUID:
                        suid.append((self.rel(full), st))
                    if st.st_mode & stat.S_ISGID:
                        sgid.append((self.rel(full), st))
                if scanned > SUID_SCAN_CAP:
                    break
        uniq = {p: s for p, s in suid}
        self.audit.stats.update(suid=len(uniq), sgid=len({p for p, _ in sgid}))
        for path, st in sorted(uniq.items()):
            name = os.path.basename(path)
            base = re.sub(r"[\d.]+$", "", name) or name
            if (name in GTFO_SUID or base in GTFO_SUID) and st.st_uid == 0:
                self.add("suid-gtfo", "HIGH", f"SUID-root {path} allows privilege escalation",
                         f"{path} mode {stat.filemode(st.st_mode)} owner uid {st.st_uid} "
                         f"(listed on GTFOBins)", f"chmod u-s {path}")
            elif name not in EXPECTED_SUID and (path.startswith(("/usr/local", "/opt"))
                                                 or st.st_uid == 0):
                self.add("suid-unusual", "LOW", f"Unusual SUID binary {path}",
                         f"{path} mode {stat.filemode(st.st_mode)} owner uid {st.st_uid}",
                         f"Verify {path} needs the SUID bit; otherwise `chmod u-s {path}`.")

    # ── docker ──────────────────────────────────────────────────────────
    def docker(self) -> None:
        for sock in ("/var/run/docker.sock", "/run/docker.sock"):
            st = self.lstat(self.p(sock))
            if st is None or stat.S_ISLNK(st.st_mode):
                continue
            mode = stat.S_IMODE(st.st_mode)
            self.audit.stats["docker_sock"] = f"{sock} {oct(mode)}"
            if mode & 0o006:
                self.add("docker-sock", "CRITICAL",
                         f"{sock} is accessible by every user ({oct(mode)})",
                         f"{sock} mode {stat.filemode(st.st_mode)}",
                         f"chmod 660 {sock} (root:docker) and fix whatever set it to {oct(mode)}.")
            break
        group = self.read(self.p("/etc/group")) or ""
        for line in group.splitlines():
            parts = line.split(":")
            if len(parts) >= 4 and parts[0] == "docker" and parts[3].strip():
                members = [m for m in parts[3].split(",") if m]
                self.add("docker-group", "LOW",
                         "Users in the docker group are root-equivalent",
                         f"docker group members: {', '.join(members)}",
                         "Keep the docker group to trusted administrators; consider rootless Docker.")

    # ── cron ────────────────────────────────────────────────────────────
    def cron(self) -> None:
        paths = [self.p("/etc/crontab")]
        for d in ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
                  "/etc/cron.monthly", "/var/spool/cron/crontabs", "/var/spool/cron"):
            base = self.p(d)
            st = self.lstat(base)
            if st and stat.S_ISDIR(st.st_mode):
                if st.st_mode & stat.S_IWOTH:
                    self.add("cron-ww", "HIGH", f"Cron directory {d} is world-writable",
                             f"{d} mode {stat.filemode(st.st_mode)}", f"chmod o-w {d}")
                try:
                    paths += [base / n for n in os.listdir(base)]
                except OSError:
                    pass
        scripts: set[str] = set()
        for path in paths:
            st = self.lstat(path)
            if st is None or not stat.S_ISREG(st.st_mode):
                continue
            rel = self.rel(path)
            if st.st_mode & stat.S_IWOTH:
                self.add("cron-ww", "HIGH", f"Cron file {rel} is world-writable",
                         f"{rel} mode {stat.filemode(st.st_mode)}", f"chmod o-w {rel}")
            if rel.startswith(("/etc/crontab", "/etc/cron.d")):
                for line in (self.read(path) or "").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or re.match(r"^\w+=", line):
                        continue
                    for tok in re.findall(r"(/[\w./-]+)", line):
                        if not tok.startswith(("/dev/", "/proc/")):
                            scripts.add(tok)
        for s in sorted(scripts):
            st = self.lstat(self.p(s))
            if st and stat.S_ISREG(st.st_mode) and st.st_mode & stat.S_IWOTH:
                self.add("cron-ww", "HIGH", f"Script run by cron is world-writable: {s}",
                         f"{s} mode {stat.filemode(st.st_mode)}", f"chmod o-w {s}")

    # ── accounts ────────────────────────────────────────────────────────
    def _passwd(self) -> list[list[str]]:
        text = self.read(self.p("/etc/passwd")) or ""
        return [ln.split(":") for ln in text.splitlines()
                if ln and not ln.startswith("#") and ln.count(":") >= 6]

    def accounts(self) -> None:
        users = self._passwd()
        self.audit.stats["accounts"] = len(users)
        for u in users:
            if u[2] == "0" and u[0] != "root":
                self.add("uid0", "CRITICAL", f"Account {u[0]} has UID 0",
                         f"/etc/passwd: {u[0]}:x:0:...", f"Remove or re-number account {u[0]}.")
            if u[1] == "":
                self.add("empty-password", "CRITICAL", f"Account {u[0]} has an empty password",
                         f"/etc/passwd: {u[0]} password field empty",
                         f"`passwd -l {u[0]}` or set a password.")
        shadow_path = self.p("/etc/shadow")
        shadow = self.read(shadow_path)
        if shadow is None:
            if shadow_path.exists():
                self.audit.notes.append("/etc/shadow not readable; empty-password check limited")
        else:
            for ln in shadow.splitlines():
                parts = ln.split(":")
                if len(parts) >= 2 and parts[1] == "":
                    self.add("empty-password", "CRITICAL",
                             f"Account {parts[0]} has an empty password",
                             f"/etc/shadow: {parts[0]} hash field empty",
                             f"`passwd -l {parts[0]}` or set a password.")
        for path, bad, sev in (("/etc/passwd", 0o022, "CRITICAL"),
                               ("/etc/shadow", 0o044 | 0o022, "CRITICAL"),
                               ("/etc/sudoers", 0o022, "CRITICAL")):
            st = self.lstat(self.p(path))
            if st and stat.S_IMODE(st.st_mode) & (bad & 0o007):
                self.add("account-file-perms", sev, f"{path} has unsafe permissions",
                         f"{path} mode {stat.filemode(st.st_mode)}",
                         f"chmod {'640' if 'shadow' in path else '644' if 'passwd' in path else '440'} {path}")

    # ── ~/.ssh ──────────────────────────────────────────────────────────
    def ssh_dirs(self) -> None:
        homes: list[tuple[str, int, Path]] = []
        if self.home_dirs is not None:
            homes = [(Path(h).name, os.getuid(), Path(h)) for h in self.home_dirs]
        else:
            for u in self._passwd():
                home = u[5]
                if home and home not in ("/", "/nonexistent") and u[2].isdigit():
                    homes.append((u[0], int(u[2]), self.p(home)))
        checked = 0
        for user, uid, home in homes:
            sshd = home / ".ssh"
            st = self.lstat(sshd)
            if st is None or not stat.S_ISDIR(st.st_mode):
                continue
            checked += 1
            rel = self.rel(sshd)
            if stat.S_IMODE(st.st_mode) & 0o022:
                self.add("ssh-dir-perms", "MEDIUM", f"{rel} is writable by group/others",
                         f"{rel} mode {stat.filemode(st.st_mode)}", f"chmod 700 {rel}")
            if st.st_uid != uid:
                self.add("ssh-dir-owner", "MEDIUM", f"{rel} is not owned by {user}",
                         f"{rel} owner uid {st.st_uid}, expected {uid}",
                         f"chown {user} {rel}")
            for name in ("authorized_keys", "authorized_keys2"):
                ak = sshd / name
                ast = self.lstat(ak)
                if ast is None:
                    continue
                if ast.st_uid not in (uid, 0):
                    self.add("ssh-authkeys-owner", "HIGH",
                             f"{self.rel(ak)} is owned by another user",
                             f"owner uid {ast.st_uid}, expected {uid}",
                             f"chown {user} {self.rel(ak)}")
                if stat.S_IMODE(ast.st_mode) & 0o022:
                    self.add("ssh-authkeys-perms", "HIGH",
                             f"{self.rel(ak)} is writable by group/others",
                             f"{self.rel(ak)} mode {stat.filemode(ast.st_mode)}",
                             f"chmod 600 {self.rel(ak)}")
            for key in sorted(sshd.glob("id_*")):
                if key.name.endswith(".pub"):
                    continue
                kst = self.lstat(key)
                if kst and stat.S_ISREG(kst.st_mode) and stat.S_IMODE(kst.st_mode) & 0o077:
                    self.add("ssh-key-perms", "HIGH",
                             f"Private key {self.rel(key)} is readable by group/others",
                             f"{self.rel(key)} mode {stat.filemode(kst.st_mode)}",
                             f"chmod 600 {self.rel(key)}")
            kh = sshd / "known_hosts"
            kst = self.lstat(kh)
            if kst and stat.S_IMODE(kst.st_mode) & 0o022:
                self.add("ssh-known-hosts-perms", "LOW",
                         f"{self.rel(kh)} is writable by group/others",
                         f"{self.rel(kh)} mode {stat.filemode(kst.st_mode)}",
                         f"chmod 644 {self.rel(kh)}")
        self.audit.stats["ssh_dirs_checked"] = checked


def _decode_addr(field_: str, v6: bool) -> tuple[str, int]:
    hexaddr, hexport = field_.split(":")
    port = int(hexport, 16)
    raw = bytes.fromhex(hexaddr)
    if v6:
        # four little-endian 32-bit words
        raw = b"".join(struct.pack(">I", struct.unpack("<I", raw[i:i + 4])[0])
                       for i in range(0, 16, 4))
        addr = socket.inet_ntop(socket.AF_INET6, raw)
        if addr.startswith("::ffff:"):
            addr = addr[7:]
    else:
        addr = socket.inet_ntop(socket.AF_INET, raw[::-1])
    return addr, port


def port_owners(proc: str = "/proc") -> dict[tuple[str, int], str]:
    """``{("tcp", 8091): "gunicorn [/root/app]"}`` for this machine's listeners."""
    aud = _Auditor("/", proc, use_tools=False)
    aud.listening()
    out: dict[tuple[str, int], str] = {}
    for l in aud.audit.listeners:
        if not l.pid or (l.proto, l.port) in out:
            continue
        try:
            cwd = os.readlink(f"{proc}/{l.pid}/cwd")
        except OSError:
            cwd = ""
        name = l.process
        if len(name) >= 15:  # comm is truncated to 15 chars; prefer argv[0]
            try:
                argv0 = Path(f"{proc}/{l.pid}/cmdline").read_bytes().split(b"\0")[0]
                name = os.path.basename(argv0.decode(errors="replace")).split()[0] or name
            except (OSError, IndexError):
                pass
        out[(l.proto, l.port)] = name + (f" [{cwd}]" if cwd and cwd != "/" else "")
    return out


def run_local_audit(root: str = "/", proc: str = "/proc", *,
                    use_tools: Optional[bool] = None,
                    home_dirs: Optional[list[str]] = None) -> LocalAudit:
    """Audit this machine (or a fixture tree under ``root``) read-only."""
    return _Auditor(root, proc, use_tools=use_tools, home_dirs=home_dirs).run()
