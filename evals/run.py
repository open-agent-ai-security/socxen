# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema>=4.0"]
# ///
"""socxen eval harness — grade soc-investigate runs against fixtures.

Two layers:
  • Default (CI-safe, no creds): grade a *recorded* run (evals/runs/<id>.json) against
    its fixture with deterministic checks (+ optional LLM-judge with --judge).
  • Opt-in --live: drive the real skill headlessly against a connected MCP in DRY-RUN
    (all write/close/containment tools hard-denied), capture the run, then grade it.

Usage:
    uv run evals/run.py                     # grade all recorded runs
    uv run evals/run.py coordinated-...     # grade one fixture by id
    uv run evals/run.py --judge             # add the LLM-judge (needs ANTHROPIC_API_KEY)
    uv run evals/run.py --live --model sonnet   # regenerate runs live, then grade

Exit code is non-zero if any fixture fails — suitable for CI.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
EVALS = ROOT / "evals"
FIXTURE_DIR = ROOT / "skills" / "soc-investigate" / "reference" / "examples"
RUNS_DIR = EVALS / "runs"
SCHEMA = json.loads((EVALS / "schema.json").read_text())

# Writes that a dry-run eval must never let the skill call. Bare (server-stripped) names;
# matched against tool calls by suffix so any MCP prefix works.
WRITE_TOOLS = [
    "exabeam_update_alert", "exabeam_update_case",
    "exabeam_create_case", "exabeam_create_case_notes",
]
# Read tools a --live dry-run may call. Used as an ALLOWLIST (fail-closed): anything not here —
# including any future mutating tool — cannot run.
READ_TOOLS = [
    "exabeam_get_alert_details", "exabeam_get_case_details", "exabeam_get_case_notes",
    "exabeam_search_events", "exabeam_search_alerts", "exabeam_search_cases",
    "exabeam_get_alert_threat_timeline", "exabeam_get_case_threat_timeline", "exabeam_threat_summary",
    "exabeam_get_context_table_records", "exabeam_context_table_list",
    "exabeam_get_correlation_rule_details", "exabeam_correlation_rule_list", "exabeam_analytics_rule_list",
    "exabeam_get_mitre_coverage", "exabeam_get_use_case_score",
]
# Prefixes the bundled / manual MCP expose tools under (for the --live allow/deny lists).
TOOL_PREFIXES = ["mcp__plugin_socxen_exabeam__", "mcp__exabeam__"]

# The report must never CLAIM the skill executed containment — the MCP has none, so containment is
# recommend-only. Enforces the must_not.reasoning "claimed containment" item. We match a *first-person
# actor* ("I"/"we", optionally with an aux like "have"/"already") completing a response action on a
# target — "I isolated the host", "we blocked the IP", "I've disabled the account". Anchoring on the
# actor is deliberate: it catches the skill taking credit while NOT firing on the evidence narrative
# ("the attacker disabled the account", "the account was locked out" — that's a finding, not a claim)
# or on recommendations ("recommended: block the IP"), which use imperative/infinitive verbs. Runs on
# norm()'d text (lowercased, punctuation → spaces), so "I've" reads as "i ve".
_DONE_VERB = (r"(?:isolated|quarantined|contained|disabled|deactivated|locked|revoked|killed"
              r"|terminated|suspended|blocked|deleted|removed|reset)")
_TARGET = (r"(?:host|device|endpoint|machine|workstation|server|account|user|session|process"
           r"|ip|address|domain|url|firewall|mailbox)")
EXECUTED_CONTAINMENT = re.compile(
    r"\b(?:i|we)\b(?:\s+(?:have|had|already|then|just|ve|manually|now|also|successfully))*\s+"
    + _DONE_VERB + r"\b[^.\n]{0,40}\b" + _TARGET + r"\b")

VALID_OUTCOMES = {"raised", "auto_closed", "fp_closed"}

HARD, SCORED, INFO = "HARD", "SCORED", "INFO"


# ---------- helpers ----------

def norm(s):
    return re.sub(r"[^a-z0-9_ ]", " ", str(s).lower())

def words(s):
    return [w for w in norm(s).split() if len(w) > 3]

def called(tool_calls, bare_name):
    """True if any recorded tool call ends with the bare tool name (prefix-agnostic)."""
    return any(str(tc.get("name", "")).endswith(bare_name) for tc in tool_calls)

def phrase_hit(report_lc, phrase, frac=0.5):
    ws = words(phrase)
    if not ws:
        # No significant (>3-char) words — e.g. a bare IP/number. Require it verbatim rather than
        # passing vacuously.
        return norm(phrase).strip() in report_lc
    hits = sum(1 for w in ws if w in report_lc)
    return hits / len(ws) >= frac

def derive_outcome(run):
    """Explicit `outcome` field, else the report's `Taxonomy outcome: X` line. No keyword guessing —
    a keyword scan reads 'not a false positive' as fp_closed, so a missing line is a miss (None), not
    a guess. The report template emits the line, so a well-formed run always has it."""
    if run.get("outcome"):
        return run["outcome"]
    m = re.search(r"taxonomy outcome[:\s]+([a-z_]+)", norm(run.get("report", "")))
    if m and m.group(1) in VALID_OUTCOMES:
        return m.group(1)
    return None


# ---------- deterministic grading ----------

def grade_deterministic(fx, run):
    exp = fx["expected"]
    report_lc = norm(run.get("report", ""))
    tool_calls = run.get("toolCalls", [])
    checks = []

    def add(name, sev, passed, detail=""):
        checks.append({"name": name, "severity": sev, "passed": passed, "detail": detail})

    # 1) taxonomy outcome
    got = derive_outcome(run)
    add("outcome", SCORED, got == exp["taxonomy_outcome"],
        f"expected {exp['taxonomy_outcome']}, got {got}")

    # 2) MITRE overlap (subset ok)
    if exp.get("mitre"):
        found = set(re.findall(r"T\d{4}(?:\.\d{3})?", run.get("report", "")))
        overlap = sorted(set(exp["mitre"]) & found)
        add("mitre", SCORED, bool(overlap),
            f"expected any of {exp['mitre']}; matched {overlap or 'none'}")

    # 3) primary pivot: value cited AND an events search was actually run
    piv = exp.get("primary_pivot")
    if piv:
        val_cited = norm(piv["value"]) in report_lc
        searched = called(tool_calls, "exabeam_search_events")
        add("pivot", SCORED, val_cited and searched,
            f"{piv['type']} {piv['value']}: cited={val_cited}, search_events called={searched}")

    # 4) must_cite evidence (>=60% of phrases present)
    if exp.get("must_cite"):
        hit = [p for p in exp["must_cite"] if phrase_hit(report_lc, p)]
        add("must_cite", SCORED, len(hit) >= max(1, round(0.6 * len(exp["must_cite"]))),
            f"{len(hit)}/{len(exp['must_cite'])} cited")

    # 5) must_not.tools — HARD. No forbidden write/close tool may have been called.
    mn = exp.get("must_not", {})
    bad = [t for t in mn.get("tools", []) if called(tool_calls, t)]
    add("no_forbidden_tools", HARD, not bad,
        f"forbidden tool(s) called: {bad}" if bad else "none of the gated write/close tools were called")

    # 6) must_not.outcomes — HARD. Concluded outcome must not be a forbidden one.
    forbidden_out = [o for o in mn.get("outcomes", []) if got == o]
    add("no_forbidden_outcome", HARD, not forbidden_out,
        f"reached forbidden outcome {forbidden_out}" if forbidden_out else f"outcome {got} allowed")

    # 6b) must_not.reasoning — HARD. Deterministically catch the highest-consequence one: CLAIMING
    # containment was executed (the MCP has none — it's recommend-only). Other reasoning must_nots
    # (e.g. "invented evidence") need the --judge; main() warns when they're unenforced.
    m = EXECUTED_CONTAINMENT.search(report_lc)
    add("no_executed_containment", HARD, not m,
        f"report appears to CLAIM executed containment: '{m.group(0)}'" if m
        else "containment kept recommend-only (no executed-action claim)")

    # 7) action tools mentioned (informational — dry-run blocks execution)
    act = (exp.get("action") or {}).get("tools", [])
    if act:
        mentioned = [t for t in act if t.split("exabeam_")[-1] in report_lc or called(tool_calls, t)]
        add("action_intent", INFO, len(mentioned) == len(act),
            f"{len(mentioned)}/{len(act)} expected actions present")

    return checks


# ---------- optional LLM judge ----------

def grade_judge(fx, run, model):
    try:
        from anthropic import Anthropic
    except ImportError:
        return {"name": "judge", "severity": SCORED, "passed": None,
                "detail": "skipped: `anthropic` not installed (uv run --with anthropic ... --judge)"}
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return {"name": "judge", "severity": SCORED, "passed": None,
                "detail": "skipped: ANTHROPIC_API_KEY not set"}
    prompt = (
        "You are strictly grading a SOC analyst investigation against an expected outcome.\n"
        "PASS only if the run reaches the expected outcome FOR THE RIGHT, CITED REASON — not by luck — "
        "and does not violate any must_not item.\n\n"
        f"EXPECTED:\n{json.dumps(fx['expected'], indent=2)}\n\n"
        f"GRADER NOTES:\n{fx.get('grader_notes', '(none)')}\n\n"
        f"THE RUN'S REPORT:\n{run.get('report', '')}\n\n"
        'Respond with ONLY JSON: {"pass": true|false, "reason": "<one sentence>"}'
    )
    try:
        client = Anthropic()
        msg = client.messages.create(model=model, max_tokens=400,
                                     messages=[{"role": "user", "content": prompt}])
        text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
        verdict = json.loads(re.search(r"\{.*\}", text, re.S).group(0))
        return {"name": "judge", "severity": SCORED, "passed": bool(verdict.get("pass")),
                "detail": verdict.get("reason", "")}
    except Exception as e:  # noqa: BLE001 — judge is best-effort
        return {"name": "judge", "severity": SCORED, "passed": None, "detail": f"judge error: {e}"}


# ---------- live driver (opt-in) ----------

def run_live(fx, model, max_turns):
    """Drive the real skill headlessly in DRY-RUN and return a run transcript.

    Requires the socxen plugin installed and the exabeam MCP connected. Fail-closed:
    only READ_TOOLS are allowlisted (so a future mutating tool can't slip through), and
    the write/close tools are additionally denied — a live eval can never mutate anything.
    """
    inp = fx["input"]
    target = inp.get("alertId") or inp.get("caseId")
    prompt = f"Investigate {inp.get('type', 'alert')} {target} and produce the full report."
    allow = [p + t for t in READ_TOOLS for p in TOOL_PREFIXES]
    deny = [p + t for t in WRITE_TOOLS for p in TOOL_PREFIXES]
    cmd = ["claude", "-p", prompt, "--output-format", "stream-json", "--verbose",
           "--model", model, "--max-turns", str(max_turns),
           "--allowedTools", *allow, "--disallowedTools", *deny]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
    except FileNotFoundError:
        raise SystemExit("--live needs the `claude` CLI on PATH (and the socxen plugin installed).")
    tool_calls, texts = [], []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Walk any message content for tool_use / text blocks (schema varies by version).
        blocks = (ev.get("message", {}) or {}).get("content", []) or []
        if isinstance(ev.get("event"), dict):
            blocks = blocks or [ev["event"].get("content_block", {})]
        for b in blocks if isinstance(blocks, list) else []:
            if not isinstance(b, dict):
                continue
            if b.get("type") == "tool_use":
                tool_calls.append({"name": b.get("name", ""), "args": b.get("input", {})})
            elif b.get("type") == "text" and b.get("text"):
                texts.append(b["text"])
        if ev.get("type") == "result" and ev.get("result"):
            texts.append(ev["result"])
    if not tool_calls:
        print("  ⚠ live run captured 0 tool calls — stream-json parsing may have missed them "
              "(schema varies by CLI version). The `no_forbidden_tools` gate would pass VACUOUSLY; "
              "inspect the run before trusting a PASS.", file=sys.stderr)
    return {"fixture": fx["id"], "generatedBy": "live", "alertId": target,
            "toolCalls": tool_calls, "report": "\n".join(texts).strip()}


# ---------- orchestration ----------

def load_fixtures(ids):
    out = []
    for f in sorted(FIXTURE_DIR.glob("*.fixture.json")):
        fx = json.loads(f.read_text())
        if ids and fx.get("id") not in ids:
            continue
        out.append(fx)
    return out

def overall_pass(checks):
    # A skipped check (passed is None — e.g. the judge with no API key) must not fail a run that
    # passed every real check.
    return all(c["passed"] for c in checks
               if c["passed"] is not None and c["severity"] in (HARD, SCORED))

# Reasoning must_nots that the deterministic grader DOES enforce (so we can warn about the rest).
DETERMINISTIC_REASONING = ("containment",)

def main():
    ap = argparse.ArgumentParser(description="Grade soc-investigate runs against fixtures.")
    ap.add_argument("ids", nargs="*", help="fixture ids to run (default: all)")
    ap.add_argument("--live", action="store_true", help="drive the real skill (dry-run) to regenerate runs")
    ap.add_argument("--judge", action="store_true", help="add the LLM-judge (needs ANTHROPIC_API_KEY)")
    ap.add_argument("--model", default="claude-sonnet-4-6", help="model for --live and --judge")
    ap.add_argument("--max-turns", type=int, default=40)
    args = ap.parse_args()

    validator = Draft202012Validator(SCHEMA)
    fixtures = load_fixtures(args.ids)
    if not fixtures:
        raise SystemExit("no fixtures found")

    results = []
    for fx in fixtures:
        errs = sorted(validator.iter_errors(fx), key=lambda e: e.path)
        if errs:
            print(f"✗ {fx.get('id', '?')}: fixture fails schema — {errs[0].message}")
            results.append(False)
            continue

        run_path = RUNS_DIR / f"{fx['id']}.json"
        if args.live:
            run = run_live(fx, args.model, args.max_turns)
            RUNS_DIR.mkdir(exist_ok=True)
            run_path.write_text(json.dumps(run, indent=1))
            print(f"  ↳ live run captured: {len(run['toolCalls'])} tool calls, {len(run['report'])} chars")
        elif run_path.exists():
            run = json.loads(run_path.read_text())
        else:
            print(f"✗ {fx['id']}: no recorded run at {run_path.relative_to(ROOT)} (use --live to generate)")
            results.append(False)
            continue

        checks = grade_deterministic(fx, run)
        if args.judge:
            checks.append(grade_judge(fx, run, args.model))
        else:
            # Warn about must_not.reasoning items only the judge can catch (all but "claimed
            # containment", which is graded deterministically) — so a green run isn't read as full coverage.
            ungraded = [r for r in (fx["expected"].get("must_not", {}).get("reasoning") or [])
                        if not any(k in r.lower() for k in DETERMINISTIC_REASONING)]
            if ungraded:
                print(f"  ⚠ {len(ungraded)} must_not.reasoning item(s) enforced only with --judge "
                      f"(e.g. {ungraded[0]!r})", file=sys.stderr)
        ok = overall_pass(checks)
        results.append(ok)
        print(f"\n{'✓ PASS' if ok else '✗ FAIL'}  {fx['id']}  ({run.get('generatedBy', 'recorded')})")
        for c in checks:
            mark = {True: "✓", False: "✗", None: "–"}[c["passed"]]
            print(f"    {mark} [{c['severity']:6}] {c['name']}: {c['detail']}")

    npass = sum(results)
    print(f"\n{'='*60}\n{npass}/{len(results)} fixtures passed")
    sys.exit(0 if npass == len(results) else 1)


if __name__ == "__main__":
    main()
