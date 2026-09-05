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
such framework object. Since observra 1.1 that's a first-class case: this shim emits through the public
`observra.emit()` (framework-agnostic instrumentation), and rotation bounds pass straight through
`initialize()` to the jsonl backend. The one remaining private touch is the exit drain
(`_worker._shutdown()`) — a public `shutdown()` is requested upstream (observra#117). Requires
observra >= 1.1 (the bridge's PEP 723 header pins `observra>=1.1,<2`).

DESIGN RULES:
  * FAIL-OPEN, ALWAYS. Telemetry is best-effort and must NEVER break or slow an investigation. A
    CONFIGURATION error (observra missing, backend misconfigured) disables logging and is swallowed; a
    single failed emit drops only THAT event and leaves the trail on — a transient fault must not switch
    off a mandatory audit log for the rest of the session.
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
_state = {"on": None, "observra": None, "backend": None, "destination": None}


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

        kwargs = {}
        # Network backends need a destination. Resolve it HERE so it can be disclosed and recorded as the
        # actual endpoint (scheme + host), not the backend keyword — Praxen PRAX-2026-09-05-007.
        if backend == "webhook":
            url = os.environ.get("SOCXEN_OBSERVRA_URL", "").strip()
            if url:
                kwargs["url"] = url
        elif backend in ("otel", "otel_log"):
            ep = os.environ.get("SOCXEN_OBSERVRA_ENDPOINT", "").strip()
            if ep:
                kwargs["endpoint"] = ep
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
            # initialize() forwards kwargs to the backend constructor (observra >= 1.1), so the rotation
            # bounds ride along. Clamped so a stray 0/negative can't turn rotation into per-event thrashing.
            kwargs["max_bytes"] = max(4096, _int_env("SOCXEN_OBSERVRA_MAX_BYTES", 10_485_760))  # >=4 KB
            kwargs["backup_count"] = max(1, _int_env("SOCXEN_OBSERVRA_BACKUPS", 5))
        observra.initialize(backend=backend, **kwargs)   # ValueError on an unknown backend -> fail-open
        observra.initialize_session()                    # a stable session/trace for this bridge process
        context.initialize_trace()

        # observra.emit() swallows its own failures into the `observra` logger. That must not be a silent
        # sink for a mandatory audit trail: route its warnings to stderr (once), same channel as our own
        # disclosures, so a dropped event is visible to the operator.
        import logging
        obs_logger = logging.getLogger("observra")
        if not any(getattr(h, "_socxen", False) for h in obs_logger.handlers):
            handler = logging.StreamHandler(sys.stderr)
            handler.setLevel(logging.WARNING)
            handler.setFormatter(logging.Formatter("bridge: observra %(levelname)s - %(message)s"))
            handler._socxen = True
            obs_logger.addHandler(handler)

        _state["observra"] = observra
        _state["emit"] = observra.emit                  # public since 1.1; bound once, off the hot path
        _state["on"] = True
        atexit.register(_shutdown)
        # Disclosed, not silent: one line so an operator can see logging is on, WHERE it goes (the resolved
        # destination, never just the backend name), and how to turn it off. The same two facts ride on
        # the mcp_session_start event so the audit trail itself attests where it was shipped.
        _state["backend"] = backend
        _state["destination"] = _destination(backend, kwargs)
        sys.stderr.write(f"bridge: structured logging on -> {backend}: {_state['destination']} "
                         f"(set SOCXEN_OBSERVRA=off to disable)\n")
        return True
    except Exception as e:  # noqa: BLE001 -- availability over telemetry, always
        return _disable(f"{type(e).__name__}: {e}")


def _destination(backend, kwargs):
    """The resolved place events go, safe to print and log: a file path, or scheme + host of a URL (never
    its path or query, which can carry a token). '' when the backend resolves it from its own env."""
    from urllib.parse import urlsplit

    def host_only(u):
        # hostname + port only: netloc would carry user:password@, and a raw fallback would carry the
        # path/query — both are where tokens live. Unparseable -> a constant, never the input.
        try:
            p = urlsplit(u if "://" in u else "//" + u)
            if not p.hostname:
                return "(unparseable endpoint)"
            scheme = p.scheme or "?"
            return f"{scheme}://{p.hostname}" + (f":{p.port}" if p.port else "")
        except Exception:  # noqa: BLE001
            return "(unparseable endpoint)"
    if backend == "jsonl":
        return kwargs.get("path", "")
    if backend == "webhook":
        return host_only(kwargs["url"]) if kwargs.get("url") else "(no SOCXEN_OBSERVRA_URL set)"
    if backend in ("otel", "otel_log"):
        env = "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT" if backend == "otel_log" else "OTEL_EXPORTER_OTLP_ENDPOINT"
        return host_only(kwargs.get("endpoint") or os.environ.get(env, "") or "http://localhost:4318")
    if backend == "exabeam":
        ep = os.environ.get("EXABEAM_ENDPOINT", "").strip()
        return host_only(ep) if ep else "(no EXABEAM_ENDPOINT set)"
    return backend


def enabled():
    """True if telemetry is configured and healthy. Configures on first call, then caches the decision."""
    if _state["on"] is None:
        _configure()
    return bool(_state["on"])


def _emit(event_type, **data):
    if not enabled():
        return
    try:
        tool = data.pop("tool_name", None)
        _state["emit"](event_type, tool_name=tool, framework=FRAMEWORK, agent_name=AGENT,
                       skill_name=SKILL, **data)
    except Exception as e:  # noqa: BLE001 -- a broken emit must never touch the investigation
        # DROP this one event; do NOT disable the whole trail. A transient per-event fault (one
        # unserializable value, observra internals changed) must not silently switch off a mandatory
        # audit log for the rest of the session. Only a configuration-level failure (in _configure)
        # disables. NOTE: observra swallows a QUEUE-full drop into a debug-level log + the
        # observra_events_dropped_total counter, below the stderr handler _configure installs, so that
        # particular drop is counted rather than announced.
        sys.stderr.write(f"bridge: telemetry event dropped ({type(e).__name__})\n")


# ---- public recording API (all no-ops when disabled; none ever raise) ------------------------------

def session_start(**config):
    """The session record doubles as the configuration attestation: which telemetry backend, where it
    ships (resolved destination), plus whatever the bridge passes (dry_run, plugin_version, gate_log).
    enabled() runs FIRST: it is what configures the pipeline and fills in backend/destination — reading
    them before it would attest an empty configuration (found in review, 2026-09-05)."""
    if not enabled():
        return
    data = {"telemetry_backend": _state.get("backend") or "",
            "telemetry_destination": _state.get("destination") or ""}
    data.update(config)                       # a caller's key wins; never a TypeError on collision
    _emit("mcp_session_start", **data)


def session_end():
    _emit("mcp_session_end")


def tool_start(tool):
    _emit("tool_start", tool_name=tool)


def tool_end(tool, duration_ms, *, defang_notes=None, hygiene_removed=None, action_fields=None,
             hygiene_kept=None, screen_failed=False):
    """Record a completed tool call.

    `action_fields`  — the SAFE identifier/enum fields of a gated write (alertId, alertStatus,
                       disposition, ...). This is the deterministic decision record: *what* the agent
                       did, on *which* object, to *what* disposition. Never free text.
    `defang_notes`   — the output-neutralizer's change notes; summarized to per-type COUNTS.
    `hygiene_removed`— the input-canonicalizer's stripped-code-point records; summarized to a COUNT and
                       the distinct code-point CLASSES. The underlying values never enter the log.
    `hygiene_kept`   — the canonicalizer's flagged-but-kept records (joiners, directional marks): same
                       count + classes shape. The text is untouched; the log is the only place the
                       signal exists, by design (no in-band marker is ever written).
    `screen_failed`  — True when input screening threw and a block passed through raw (fail-open)."""
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
    if hygiene_kept:
        classes = list(dict.fromkeys(r["cp"] for r in hygiene_kept))
        data["hygiene_kept"] = len(hygiene_kept)
        data["hygiene_kept_classes"] = ",".join(classes)
    if screen_failed:
        data["hygiene_screen_failed"] = True
    _emit("tool_end", tool_name=tool, **data)


def tool_error(tool, duration_ms, exc, stage=None):
    """`stage` names the layer that raised: "neutralize" is the write-side guardrail refusing to forward
    (fail-closed — a guardrail acting, recorded as such), "remote" is the upstream call."""
    data = {"duration_ms": round(duration_ms, 1), "error_class": type(exc).__name__}
    if stage:
        data["stage"] = stage
        if stage == "neutralize":
            data["guardrail_refused"] = True
    _emit("tool_error", tool_name=tool, **data)


def _shutdown():
    """Best-effort flush of the background worker at process exit. Guarded — exit must never error.
    The last private reach-in this shim carries: observra has no public shutdown()/flush() yet, and the
    tail of an audit trail (the gated write, session_end) is exactly what's still queued at exit.
    Upstream RFE: observra#117."""
    try:
        if not _state.get("on"):
            return
        session_end()
        worker = getattr(_state["observra"], "_worker", None)
        if worker is not None:
            worker._shutdown()   # drains the queue to the backend and closes it
    except Exception:  # noqa: BLE001
        pass
