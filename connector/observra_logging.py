# /// script
# requires-python = ">=3.11"
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Structured, durable agent telemetry for the Exabeam MCP bridge — ON by default, for assurance.

Built on **observra** (https://open-agent-ai-security.github.io/observra/), an agent-telemetry SDK.

Why here: the bridge sits in the path of *every* tool call the `soc-investigate` agent makes, so it is
the natural place to record what the agent did — which Exabeam tools it called, how long they took,
whether they succeeded, **the gated action it took** (which alert/case, to what disposition), and, uniquely
useful for this project, **when the two deterministic guardrails actually fired** (input canonicalization
stripping a smuggling code point; output neutralization defanging a formula / phishing link before a
write). That turns the log into a machine-parseable audit trail — the thing a production SOC needs to
reconstruct a session or drive anomaly detection, in place of the free-form markdown report alone.

DEFAULT ON. A good agent keeps an audit trail. Logging runs unless you explicitly turn it off
(`SOCXEN_OBSERVRA=off`). The default backend is a local, rotating JSON-lines file — no network egress.

Not an exact framework fit, by design: observra's `create_plugin()` hooks a supported *framework* (ADK,
Claude SDK, LangChain, ...). Our "agent" is Claude Code driving a skill over an MCP bridge — there is no
such framework object. But observra already ships CIM support for `framework="mcp"` / `"claude_code"` and
MCP/skill/tool event types, so this is a small **custom adapter**: it emits observra `TelemetryEvent`s
through the public `create_event()` and the pipeline's queue.

DESIGN RULES:
  * FAIL-OPEN, ALWAYS. Telemetry is best-effort. Any error (observra missing, backend misconfigured, an
    emit failure) disables logging and is swallowed. Logging must NEVER break or slow an investigation.
  * PRIVACY BY CONSTRUCTION. We log *metadata* about the agent's actions — tool names, durations, gated-
    action IDs/enums (alertId, alertStatus, disposition, ...), guardrail counts, stripped code-point
    classes — never the free-text field values / notes / payloads the guardrails neutralize. The audit
    log records *what was decided*, not the raw evidence. (observra also applies its own PII redaction.)
  * BOUNDED. The jsonl backend rotates (default 10 MB × 5 backups ≈ 60 MB ceiling) so it never grows
    without limit.

Configuration (all optional):
    SOCXEN_OBSERVRA=jsonl              # default; also: off | exabeam | otel | otel_log | webhook
    SOCXEN_OBSERVRA_PATH=~/.socxen/telemetry.jsonl     # jsonl backend location (default)
    SOCXEN_OBSERVRA_MAX_BYTES=10485760                 # rotate at this size (default 10 MB)
    SOCXEN_OBSERVRA_BACKUPS=5                          # keep this many rotated files (default 5)

The `exabeam` backend routes telemetry back into Exabeam using the bridge's own creds — on-brand, but it
makes network calls, so it is never the default; `jsonl` (local, offline, rotating) is.
"""
import atexit
import os
import sys

__all__ = ["enabled", "session_start", "session_end", "tool_start", "tool_end", "tool_error"]

SKILL = "soc-investigate"
AGENT = "socxen"
FRAMEWORK = "mcp"
_DEFAULT_BACKEND = "jsonl"                              # ON by default — assurance is the default posture
_DEFAULT_PATH = "~/.socxen/telemetry.jsonl"
_OFF_VALUES = {"off", "0", "false", "no", "none", "disabled"}

# Lazily-populated runtime state. `on` is tri-state: None = not yet configured, True/False = decided.
_state = {"on": None, "observra": None}


def _disable(reason=None):
    _state["on"] = False
    if reason:
        sys.stderr.write(f"bridge: observra logging disabled ({reason})\n")
    return False


def _int_env(name, default):
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _configure():
    """Decide once whether telemetry is on (it is, unless explicitly off) and stand up the observra
    pipeline. Fail-open — any problem disables logging without touching the investigation."""
    backend = os.environ.get("SOCXEN_OBSERVRA", "").strip().lower() or _DEFAULT_BACKEND
    if backend in _OFF_VALUES:
        return _disable()
    try:
        import observra
        from observra.core import context
        from observra.core.events import create_event

        kwargs = {}
        if backend == "jsonl":
            path = os.path.expanduser(os.environ.get("SOCXEN_OBSERVRA_PATH", _DEFAULT_PATH))
            if path.startswith("~"):
                # HOME/USERPROFILE unset (some daemon/container contexts) -> expanduser was a no-op. Don't
                # create a literal "~" directory under CWD; fall back to the temp dir and say where.
                import tempfile
                path = os.path.join(tempfile.gettempdir(), "socxen-telemetry.jsonl")
                sys.stderr.write(f"bridge: HOME not set; audit log -> {path}\n")
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            kwargs["path"] = path
        observra.initialize(backend=backend, **kwargs)   # ValueError on an unknown backend -> fail-open
        context.initialize_session()                     # a stable session/trace for this bridge process
        context.initialize_trace()

        if backend == "jsonl":
            # observra's initialize() forwards only `path` to the jsonl backend (observra#84), so set the
            # rotation bounds on the constructed instance (it reads these per write). Values are clamped so
            # a stray 0/negative can't turn rotation into per-event thrashing.
            storage = getattr(getattr(observra, "_worker", None), "_storage", None)
            if storage is not None:
                storage.max_bytes = max(4096, _int_env("SOCXEN_OBSERVRA_MAX_BYTES", 10_485_760))  # >=4 KB
                storage.backup_count = max(1, _int_env("SOCXEN_OBSERVRA_BACKUPS", 5))
            else:
                # Reach-in failed (observra internals changed): observra's own default (10 MB x 5) still
                # bounds the file, so the audit log stays bounded — just note it isn't operator-tunable.
                sys.stderr.write("bridge: observra storage internals not found; "
                                 "using its default rotation bounds (not tunable this run)\n")

        _state["observra"] = observra
        _state["create_event"] = create_event           # bind once, off the per-event hot path
        _state["queue"] = observra._queue_proxy          # the pipeline's swappable sink (survives re-init)
        _state["on"] = True
        atexit.register(_shutdown)
        # Disclosed, not silent: one line so an operator can see logging is on and how to turn it off.
        where = kwargs.get("path", backend)
        sys.stderr.write(f"bridge: structured logging on -> {where} (set SOCXEN_OBSERVRA=off to disable)\n")
        return True
    except Exception as e:  # noqa: BLE001 -- availability over telemetry, always
        return _disable(f"{type(e).__name__}: {e}")


def enabled():
    """True if telemetry is configured and healthy. Configures on first call, then caches the decision."""
    if _state["on"] is None:
        _configure()
    return bool(_state["on"])


def _emit(event_type, **data):
    if not enabled():
        return
    try:
        ev = _state["create_event"](event_type, framework=FRAMEWORK, agent_name=AGENT,
                                    skill_name=SKILL, **data)
        _state["queue"].put_nowait(ev)
    except Exception as e:  # noqa: BLE001 -- a broken emit must never touch the investigation
        # DROP this one event; do NOT disable the whole trail. A transient per-event fault (a burst that
        # fills the queue, one unserializable value) must not silently switch off a mandatory audit log
        # for the rest of the session. Only a configuration-level failure (in _configure) disables.
        sys.stderr.write(f"bridge: telemetry event dropped ({type(e).__name__})\n")


# ---- public recording API (all no-ops when disabled; none ever raise) ------------------------------

def session_start():
    _emit("mcp_session_start")


def session_end():
    _emit("mcp_session_end")


def tool_start(tool):
    _emit("tool_start", tool_name=tool)


def tool_end(tool, duration_ms, *, defang_notes=None, hygiene_removed=None, action_fields=None):
    """Record a completed tool call.

    `action_fields`  — the SAFE identifier/enum fields of a gated write (alertId, alertStatus,
                       disposition, ...). This is the deterministic decision record: *what* the agent
                       did, on *which* object, to *what* disposition. Never free text.
    `defang_notes`   — the output-neutralizer's change notes; summarized to per-type COUNTS.
    `hygiene_removed`— the input-canonicalizer's stripped-code-point records; summarized to a COUNT and
                       the distinct code-point CLASSES. The underlying values never enter the log."""
    data = {"duration_ms": round(duration_ms, 1)}
    if action_fields:
        for key, val in action_fields.items():           # -> data["action.alertStatus"] = "closed", ...
            data[f"action.{key}"] = val
    if defang_notes:
        for note in defang_notes:                        # -> {"defang_formula": 1, "defang_link": 2}
            dkey = "defang_" + str(note.get("type", "other"))
            data[dkey] = data.get(dkey, 0) + 1
    if hygiene_removed:
        classes = list(dict.fromkeys(r["cp"] for r in hygiene_removed))   # distinct U+XXXX, order-stable
        data["hygiene_stripped"] = len(hygiene_removed)
        data["hygiene_classes"] = ",".join(classes)
    _emit("tool_end", tool_name=tool, **data)


def tool_error(tool, duration_ms, exc):
    _emit("tool_error", tool_name=tool, duration_ms=round(duration_ms, 1),
          error_class=type(exc).__name__)


def _shutdown():
    """Best-effort flush of the background worker at process exit. Guarded — exit must never error."""
    try:
        if not _state.get("on"):
            return
        session_end()
        worker = getattr(_state["observra"], "_worker", None)
        if worker is not None:
            worker._shutdown()   # drains the queue to the backend and closes it
    except Exception:  # noqa: BLE001
        pass
