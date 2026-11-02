"""
Long-running, resumable, multi-target autonomous jobs.

A :class:`Job` owns a target list, a scope, and a budget. :class:`JobRunner`
drives one :class:`~suvari.auto.loop.AutoLoop` per target — sequentially inside
a target (evidence integrity), in parallel across targets (``concurrency``) —
with a single global rate limiter and request budget.

On-disk layout (everything relative to the job directory)::

    output/jobs/<job_id>/
      checkpoint.json            job + per-target progress, rewritten atomically
                                 after every turn
      job.log                    run log
      targets/<key>.state.json   per-target hypotheses / decision log / findings
      evidence/<key>/E001.json   per-target evidence (no cross-target sharing)
      evidence/<key>/evidence.md
      reports/auto-<ts>.md       one report per job (interim until final)

If the process dies, ``JobManager.load(job_id)`` + ``JobRunner.run()`` resumes:
finished targets are skipped, a half-scanned target reloads its state file and
continues from its last turn (already-tried actions are never repeated).
SIGINT/SIGTERM stop the job cleanly after the in-flight probe, mark it
``paused`` and keep it resumable.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import signal
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .executor import Executor, RateLimiter
from .loop import AutoLoop
from .planner import Planner
from .scope import Scope, ScopeError, Target, expand_targets, system_resolver
from .state import ScanState

log = logging.getLogger("suvari.auto.jobs")

DEFAULT_JOBS_ROOT = Path("output") / "jobs"

# job statuses
QUEUED, RUNNING, PAUSED, DONE, FAILED = "queued", "running", "paused", "done", "failed"
JOB_STATUSES = (QUEUED, RUNNING, PAUSED, DONE, FAILED)

# target statuses; the first three are resumable
T_PENDING, T_RUNNING, T_PAUSED = "pending", "running", "paused"
T_DONE, T_UNREACHABLE, T_BLOCKED, T_ERROR = "done", "unreachable", "blocked", "error"
RESUMABLE_TARGET = (T_PENDING, T_RUNNING, T_PAUSED)

STOP_INTERRUPTED = "interrupted"

_JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$")


# ── helpers ──────────────────────────────────────────────────────────────

def parse_duration(spec) -> Optional[float]:
    """``"90"``/``90`` -> 90s, ``"30m"``, ``"2h"``, ``"1h30m"``, ``"1d"``."""
    if spec is None or spec == "":
        return None
    if isinstance(spec, (int, float)):
        return float(spec)
    s = str(spec).strip().lower()
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return float(s)
    parts = re.findall(r"(\d+(?:\.\d+)?)\s*([dhms])", s)
    if not parts or re.sub(r"(\d+(?:\.\d+)?)\s*([dhms])", "", s).strip():
        raise ValueError(f"invalid duration: {spec!r} (use e.g. 90s, 30m, 2h, 1h30m)")
    mult = {"d": 86400, "h": 3600, "m": 60, "s": 1}
    return sum(float(n) * mult[u] for n, u in parts)


def format_duration(seconds: float) -> str:
    seconds = int(seconds or 0)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m:02d}m{s:02d}s" if h else f"{m}m{s:02d}s"


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


class MeteredLLM:
    """Wrap an LLM client to count calls and tokens for the ``--max-tokens`` budget.

    Uses the provider-reported usage when the client exposes it, otherwise a
    ~4 chars/token estimate of prompt + reply.
    """

    def __init__(self, inner):
        self.inner = inner
        self._lock = threading.Lock()
        self.calls = 0
        self.est_tokens = 0

    def chat(self, messages, **kw):
        text = self.inner.chat(messages, **kw)
        est = (sum(len(str(m.get("content", ""))) for m in messages) + len(text or "")) // 4
        with self._lock:
            self.calls += 1
            self.est_tokens += est
        return text

    def __getattr__(self, name):
        # forward `model`, `last_usage`, ... so the planner's usage tracker
        # still sees exact provider-reported counts through the wrapper
        return getattr(self.inner, name)

    def tokens(self) -> int:
        u = getattr(self.inner, "usage", None) or {}
        reported = int(u.get("prompt_tokens", 0)) + int(u.get("completion_tokens", 0))
        return reported if reported > 0 else self.est_tokens

    def snapshot(self) -> dict:
        u = getattr(self.inner, "usage", None) or {}
        return {"calls": self.calls,
                "prompt_tokens": int(u.get("prompt_tokens", 0)),
                "completion_tokens": int(u.get("completion_tokens", 0)),
                "tokens": self.tokens()}


# ── model ────────────────────────────────────────────────────────────────

@dataclass
class TargetProgress:
    url: str
    key: str
    host: str
    port: int
    status: str = T_PENDING
    turns: int = 0
    findings: int = 0
    last_hypothesis: str = ""
    stop_reason: str = ""
    started_at: Optional[float] = None
    finished_at: Optional[float] = None

    @property
    def netloc(self) -> str:
        return Target(self.url, self.host, self.port).netloc

    @property
    def state_rel(self) -> str:
        return f"targets/{self.key}.state.json"

    @property
    def evidence_rel(self) -> str:
        return f"evidence/{self.key}"


def _new_counters() -> dict:
    return {"requests": 0, "blocked": 0, "turns": 0, "findings": 0,
            "elapsed": 0.0, "runs": 0, "llm_calls": 0, "llm_tokens": 0}


@dataclass
class Job:
    id: str
    targets: list[TargetProgress]
    scope: list[str]
    budget: dict
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    status: str = QUEUED
    checkpoint: str = "checkpoint.json"
    counters: dict = field(default_factory=_new_counters)
    engine: dict = field(default_factory=dict)       # dry_run / provider / model
    allow_large_scope: bool = False
    stop_reason: str = ""
    report: str = ""
    blocked: list = field(default_factory=list)      # scope refusals
    history: list = field(default_factory=list)      # one entry per run

    def to_dict(self) -> dict:
        d = asdict(self)
        d["targets"] = [asdict(t) for t in self.targets]
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Job":
        allowed = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        clean = {k: v for k, v in data.items() if k in allowed}
        clean["targets"] = [TargetProgress(**t) for t in data.get("targets", [])]
        counters = _new_counters()
        counters.update(data.get("counters", {}))
        clean["counters"] = counters
        return cls(**clean)

    def target_counts(self) -> dict:
        out: dict[str, int] = {}
        for t in self.targets:
            out[t.status] = out.get(t.status, 0) + 1
        return out


# ── manager ──────────────────────────────────────────────────────────────

class JobManager:
    """Create, persist, load and list jobs under a jobs root directory."""

    def __init__(self, root: Path = DEFAULT_JOBS_ROOT):
        self.root = Path(root)

    def job_dir(self, job_id: str) -> Path:
        if not _JOB_ID_RE.match(job_id) or ".." in job_id:
            raise ValueError(f"invalid job id: {job_id!r}")
        return self.root / job_id

    def create(self, target_specs: list[str], *, scope_specs: Optional[list[str]] = None,
               extra_scope: Optional[list[str]] = None, allow_large_scope: bool = False,
               duration: Optional[float] = 300.0, max_requests: Optional[int] = None,
               max_tokens: Optional[int] = None, max_steps: int = 20,
               rate_per_min: int = 60, concurrency: int = 1,
               dry_run: bool = False, provider: Optional[str] = None,
               model: Optional[str] = None, resolver=system_resolver,
               job_id: Optional[str] = None) -> Job:
        """Expand targets, build the scope, mark out-of-scope targets blocked.

        Scope defaults to the targets themselves; ``scope_specs`` (e.g. from
        ``--scope-file``) replaces that default with an explicit allowlist, and
        ``extra_scope`` (``--allow-host``) is always added. Raises
        :class:`ScopeError` on bad input or an unpermitted large range.
        """
        targets = expand_targets(target_specs, allow_large=allow_large_scope)
        if not targets:
            raise ScopeError("no targets given")
        entries = list(scope_specs) if scope_specs else list(target_specs)
        entries += list(extra_scope or [])
        scope = Scope(entries, allow_large=allow_large_scope, resolver=resolver)

        job = Job(
            id=job_id or f"job-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(2)}",
            targets=[], scope=entries, allow_large_scope=allow_large_scope,
            budget={"duration": duration, "max_requests": max_requests,
                    "max_tokens": max_tokens, "max_steps": max_steps,
                    "rate_per_min": rate_per_min, "concurrency": max(1, concurrency)},
            engine={"dry_run": dry_run, "provider": provider, "model": model},
        )
        used_keys: set[str] = set()
        for t in targets:
            key = t.key
            n = 2
            while key in used_keys:
                key, n = f"{t.key}-{n}", n + 1
            used_keys.add(key)
            tp = TargetProgress(url=t.url, key=key, host=t.host, port=t.port)
            reason = scope.check(t.url)
            if reason is not None:
                tp.status, tp.stop_reason = T_BLOCKED, f"blocked by scope: {reason}"
                job.blocked.append(scope.record_blocked(t.url, reason, source="target"))
            job.targets.append(tp)
        job.counters["blocked"] = len(job.blocked)
        self.job_dir(job.id).mkdir(parents=True, exist_ok=False)
        self.save(job)
        return job

    def save(self, job: Job) -> Path:
        job.updated_at = time.time()
        path = self.job_dir(job.id) / job.checkpoint
        _atomic_write(path, json.dumps(job.to_dict(), indent=2))
        return path

    def load(self, job_id: str) -> Job:
        path = self.job_dir(job_id) / "checkpoint.json"
        if not path.exists():
            raise FileNotFoundError(f"no such job: {job_id} ({path})")
        return Job.from_dict(json.loads(path.read_text()))

    def list(self) -> list[Job]:
        if not self.root.exists():
            return []
        jobs = []
        for d in self.root.iterdir():
            cp = d / "checkpoint.json"
            if d.is_dir() and cp.exists():
                try:
                    jobs.append(Job.from_dict(json.loads(cp.read_text())))
                except (OSError, ValueError, TypeError) as e:
                    log.warning("unreadable checkpoint %s: %s", cp, e)
        return sorted(jobs, key=lambda j: j.created_at, reverse=True)

    def latest_resumable(self) -> Optional[Job]:
        for j in self.list():
            if j.status != DONE:
                return j
        return None


# ── runner ───────────────────────────────────────────────────────────────

class JobRunner:
    """Execute (or resume) one job until it finishes, is interrupted, or a
    budget runs out. Always leaves a consistent checkpoint and a report."""

    def __init__(self, job: Job, manager: JobManager, llm=None, *,
                 clock: Callable[[], float] = time.monotonic,
                 resolver=system_resolver,
                 on_turn: Optional[Callable[["JobRunner", TargetProgress], None]] = None,
                 on_event: Optional[Callable[[str, str], None]] = None,
                 handle_signals: bool = True, reach_timeout: float = 3.0,
                 probe_timeout: int = 15):
        self.job = job
        self.manager = manager
        self.dir = manager.job_dir(job.id)
        self.llm = MeteredLLM(llm) if llm is not None else None
        self.clock = clock
        self.resolver = resolver
        self.on_turn = on_turn
        self.on_event = on_event
        self.handle_signals = handle_signals
        self.reach_timeout = reach_timeout
        self.probe_timeout = probe_timeout
        self._lock = threading.RLock()
        self._stop_reason: Optional[str] = None
        self._llm_base = (job.counters.get("llm_calls", 0), job.counters.get("llm_tokens", 0))

    # ── stop conditions ─────────────────────────────────────────────────
    def request_stop(self, reason: str = STOP_INTERRUPTED) -> None:
        with self._lock:
            if self._stop_reason is None:
                self._stop_reason = reason
                self._event("stop", reason)
        self.limiter.cancel()

    def _elapsed(self) -> float:
        return self._elapsed0 + (self.clock() - self._t0)

    def _tokens(self) -> int:
        return self._llm_base[1] + (self.llm.tokens() if self.llm else 0)

    def check_stop(self) -> Optional[str]:
        """Job-level stop reason (sticky once set), or None to keep going."""
        with self._lock:
            if self._stop_reason:
                return self._stop_reason
            b = self.job.budget
            if b.get("duration") and self._elapsed() >= b["duration"]:
                self._stop_reason = f"duration budget reached ({format_duration(b['duration'])})"
            elif self.limiter.exhausted():
                self._stop_reason = f"max-requests reached ({b['max_requests']})"
            elif b.get("max_tokens") and self._tokens() >= b["max_tokens"]:
                self._stop_reason = f"max-tokens reached ({b['max_tokens']})"
            if self._stop_reason:
                self._event("stop", self._stop_reason)
                self.limiter.cancel()
            return self._stop_reason

    # ── persistence ─────────────────────────────────────────────────────
    def checkpoint(self) -> None:
        with self._lock:
            c = self.job.counters
            c["requests"] = self.limiter.count
            c["elapsed"] = round(self._elapsed(), 3)
            c["turns"] = sum(t.turns for t in self.job.targets)
            c["findings"] = sum(t.findings for t in self.job.targets)
            self.job.blocked = list(self.scope.blocked)
            c["blocked"] = len(self.job.blocked)
            if self.llm is not None:
                c["llm_calls"] = self._llm_base[0] + self.llm.calls
                c["llm_tokens"] = self._tokens()
            self.manager.save(self.job)

    def write_report(self, final: bool = False) -> Path:
        from .report import write_job_report
        with self._lock:
            path = write_job_report(self.job, self.dir, final=final)
            self.job.report = str(path.relative_to(self.dir))
            return path

    def _event(self, kind: str, msg: str) -> None:
        log.info("[%s] %s", kind, msg)
        if self.on_event is not None:
            try:
                self.on_event(kind, msg)
            except Exception:  # noqa: BLE001 - display must not break the job
                log.exception("on_event failed")

    # ── main ────────────────────────────────────────────────────────────
    def run(self) -> dict:
        job = self.job
        if job.status == DONE:
            raise RuntimeError(f"job {job.id} is already done; nothing to resume")
        b = job.budget
        self.scope = Scope(job.scope, allow_large=job.allow_large_scope,
                           resolver=self.resolver)
        self.scope.blocked = list(job.blocked)
        self.limiter = RateLimiter(b.get("rate_per_min", 60), b.get("max_requests"),
                                   start_count=job.counters.get("requests", 0))
        self._t0 = self.clock()
        self._elapsed0 = float(job.counters.get("elapsed", 0.0))

        log_handler = logging.FileHandler(self.dir / "job.log")
        log_handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(threadName)s %(name)s: %(message)s"))
        auto_log = logging.getLogger("suvari.auto")
        auto_log.addHandler(log_handler)
        if auto_log.level == logging.NOTSET or auto_log.level > logging.INFO:
            auto_log.setLevel(logging.INFO)

        resumed = job.counters.get("runs", 0) > 0
        job.status = RUNNING
        job.stop_reason = ""
        job.counters["runs"] = job.counters.get("runs", 0) + 1
        job.history.append({"started_at": time.time(), "resumed": resumed})
        self.checkpoint()
        self._event("start", f"{'resuming' if resumed else 'starting'} {job.id}: "
                             f"{len(job.targets)} target(s)")

        old_handlers = self._install_signals()
        try:
            self._run_targets()
            status, reason = self._final_status()
            job.status, job.stop_reason = status, reason
        except BaseException as e:
            job.status, job.stop_reason = FAILED, f"error: {e!r}"
            raise
        finally:
            self._restore_signals(old_handlers)
            job.history[-1].update(ended_at=time.time(), status=job.status,
                                   stop_reason=job.stop_reason)
            self.checkpoint()
            try:
                report = self.write_report(final=(job.status == DONE))
                self.checkpoint()
            finally:
                auto_log.removeHandler(log_handler)
                log_handler.close()
        self._event("end", f"{job.id} {job.status}: {job.stop_reason}")
        return {"job_id": job.id, "status": job.status, "stop_reason": job.stop_reason,
                "report": str(report), "dir": str(self.dir),
                "counters": dict(job.counters),
                "targets": [asdict(t) for t in job.targets]}

    def _run_targets(self) -> None:
        pending = [t for t in self.job.targets if t.status in RESUMABLE_TARGET]
        workers = max(1, int(self.job.budget.get("concurrency", 1)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="target") as pool:
            futures = {pool.submit(self._run_target_safe, t): t for t in pending}
            not_done = set(futures)
            while not_done:
                # short timeout keeps the main thread responsive to signals
                _, not_done = wait(not_done, timeout=0.5, return_when=FIRST_COMPLETED)

    def _final_status(self) -> tuple[str, str]:
        reason = self._stop_reason
        if reason == STOP_INTERRUPTED:
            return PAUSED, reason
        left = [t for t in self.job.targets if t.status in RESUMABLE_TARGET]
        if not left:
            return DONE, reason or "all targets finished"
        if reason:  # budget exhausted with targets left: finish cleanly
            return DONE, f"{reason}; {len(left)} target(s) not completed"
        return PAUSED, "stopped with targets remaining"

    # ── per target ──────────────────────────────────────────────────────
    def _run_target_safe(self, t: TargetProgress) -> None:
        try:
            self._run_target(t)
        except Exception as e:  # noqa: BLE001 - one target must not sink the job
            log.exception("target %s failed", t.url)
            with self._lock:
                t.status, t.stop_reason = T_ERROR, f"error: {e!r}"
                t.finished_at = time.time()
            self.checkpoint()
            self._event("target-error", f"{t.url}: {e!r}")

    def _run_target(self, t: TargetProgress) -> None:
        if self.check_stop():
            return  # left resumable
        b = self.job.budget
        state_file = self.dir / t.state_rel
        executor = Executor([t.netloc], rate_per_min=b.get("rate_per_min", 60),
                            default_timeout=self.probe_timeout,
                            scope=self.scope, limiter=self.limiter)

        if not state_file.exists():
            ok, why = executor.tcp_reachable(t.url, timeout=self.reach_timeout)
            if not ok:
                if "not sent" in why:
                    self.check_stop()
                    return
                with self._lock:
                    t.status, t.stop_reason = T_UNREACHABLE, why
                    t.finished_at = time.time()
                self.checkpoint()
                self._event("target-skip", f"{t.url}: {why}")
                return

        layout = dict(state_file=state_file,
                      evidence_dir=self.dir / t.evidence_rel,
                      evidence_md=self.dir / t.evidence_rel / "evidence.md",
                      evidence_rel=t.evidence_rel)
        if state_file.exists():
            state = ScanState.load(self.dir, **layout)
        else:
            state = ScanState(self.dir, target=t.url, allowed_hosts=[t.netloc],
                              budget={"max_steps": b.get("max_steps"), "safe": True,
                                      "rate_per_min": b.get("rate_per_min")},
                              **layout)

        with self._lock:
            t.status = T_RUNNING
            t.started_at = t.started_at or time.time()
        self.checkpoint()
        self._event("target-start", f"{t.url} (turn {state.turn})")

        def on_blocked(url: str, reason: str) -> None:
            self.scope.record_blocked(url, reason, source=f"planner:{t.key}")

        planner = Planner(t.url, llm=self.llm,
                          dry_run=bool(self.job.engine.get("dry_run")),
                          on_blocked=on_blocked)

        def after_turn() -> None:
            with self._lock:
                t.turns = state.turn
                t.findings = len(state.findings)
                if state.decision_log:
                    d = state.decision_log[-1]
                    t.last_hypothesis = d.get("hypothesis_id", "")
            self.checkpoint()
            if self.on_turn is not None:
                self.on_turn(self, t)

        loop = AutoLoop(state, planner, executor,
                        max_steps=int(b.get("max_steps") or 20),
                        time_budget=float("inf"),
                        should_stop=self.check_stop, on_turn=after_turn)
        result = loop.run()

        with self._lock:
            t.turns = state.turn
            t.findings = len(state.findings)
            t.stop_reason = result["stop_reason"]
            if self._stop_reason and result["stop_reason"] == self._stop_reason:
                t.status = T_PAUSED
            else:
                t.status = T_DONE
                t.finished_at = time.time()
        self.checkpoint()
        self._event("target-end", f"{t.url}: {t.status} — {t.turns} turns, "
                                  f"{t.findings} findings ({t.stop_reason})")
        # interim report after every finished target
        self.write_report(final=False)

    # ── signals ─────────────────────────────────────────────────────────
    def _install_signals(self):
        if not self.handle_signals or threading.current_thread() is not threading.main_thread():
            return None
        old = {}

        def handler(signum, _frame):
            self.request_stop(STOP_INTERRUPTED)

        for sig in (signal.SIGINT, signal.SIGTERM):
            old[sig] = signal.signal(sig, handler)
        return old

    @staticmethod
    def _restore_signals(old) -> None:
        if old:
            for sig, h in old.items():
                signal.signal(sig, h)
