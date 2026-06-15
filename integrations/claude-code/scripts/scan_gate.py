# SPDX-FileCopyrightText: Copyright (c) 2026 Abhiram Dwivedi
# SPDX-License-Identifier: Apache-2.0

"""SkillSpector PreToolUse gate for Claude Code.

Reads a Claude Code PreToolUse hook event on stdin. When the agent's tool call
fetches a skill from a *scannable* source (a ``git clone`` URL or a ``.zip``
archive URL in a Bash command), it scans the target with ``skillspector scan``
and returns an ``allow`` / ``ask`` / ``deny`` decision derived from the risk
recommendation. For anything it does not recognise as a skill fetch, it stays
out of the way (no decision) so normal commands are unaffected.

Decision policy (the recommendation maps directly to a decision):

    SAFE            -> allow
    CAUTION         -> ask    (override via SKILLSPECTOR_GATE_CAUTION=allow|deny)
    DO_NOT_INSTALL  -> deny

Failure modes:
    skillspector not on PATH        -> allow + a warning (gate skipped; do not
                                       break the user's workflow when the tool
                                       isn't installed)
    scan ran but failed/unparseable -> ask (fail toward caution)

Security: the extracted target is passed to ``skillspector scan`` as an argv
element with ``shell=False`` — it is never interpolated into a shell string, so
a hostile command/URL cannot inject anything into the gate's own subprocess.

This is *defense-in-depth*: a PreToolUse hook only fires on the agent's tool
calls within a session. It cannot intercept a human running an install in their
own terminal (that is the APM package's job).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys

SAFE = "SAFE"
CAUTION = "CAUTION"
DO_NOT_INSTALL = "DO_NOT_INSTALL"

SCAN_TIMEOUT_SECONDS = 120

# `git clone [opts] <url> [dir]` — capture the first http(s)/git URL argument.
_GIT_CLONE = re.compile(
    r"\bgit\s+clone\b[^\n]*?\s(?P<url>(?:https?://|git://|git@)\S+)",
    re.IGNORECASE,
)
# A direct fetch of a skill archive (curl/wget <url>.zip).
_ARCHIVE_URL = re.compile(r"(?P<url>https?://\S+\.zip)\b", re.IGNORECASE)


def _read_event() -> dict:
    try:
        return json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        return {}


def extract_target(tool_name: str, tool_input: dict) -> str | None:
    """Return a scannable target (URL) if the tool call fetches a skill, else None.

    Conservative on purpose: only acts on ``git clone`` URLs and ``.zip`` archive
    URLs in Bash commands, both of which ``skillspector scan`` accepts directly.
    Unrecognised commands return ``None`` so the gate does not interfere.
    """
    if tool_name != "Bash":
        return None
    command = str(tool_input.get("command") or "")
    match = _GIT_CLONE.search(command) or _ARCHIVE_URL.search(command)
    return match.group("url") if match else None


def scan(target: str) -> tuple[str, dict | None]:
    """Run ``skillspector scan`` on *target*. Returns ``(status, report)``.

    status is ``"ok"`` (report parsed), ``"no_tool"`` (skillspector not on PATH),
    or ``"error"`` (scan failed / unparseable).
    """
    executable = shutil.which("skillspector")
    if executable is None:
        return "no_tool", None
    try:
        # argv list + shell=False: the untrusted target is a single argument.
        proc = subprocess.run(
            [executable, "scan", target, "--no-llm", "--format", "json"],
            capture_output=True,
            text=True,
            shell=False,
            timeout=SCAN_TIMEOUT_SECONDS,
        )
    except (subprocess.TimeoutExpired, OSError):
        return "error", None
    # skillspector exit codes: 0 (score <= 50), 1 (> 50), 2 (error). Both 0 and 1
    # produce a JSON report; only 2 means the scan itself failed.
    if proc.returncode == 2:
        return "error", None
    try:
        return "ok", json.loads(proc.stdout)
    except json.JSONDecodeError:
        return "error", None


def decide(report: dict) -> tuple[str, str]:
    """Map a SkillSpector report to a ``(permissionDecision, reason)``."""
    assessment = report.get("risk_assessment") or {}
    recommendation = assessment.get("recommendation")
    score = assessment.get("score")
    if recommendation == DO_NOT_INSTALL:
        return "deny", f"SkillSpector: DO_NOT_INSTALL (risk {score}/100)."
    if recommendation == CAUTION:
        policy = os.environ.get("SKILLSPECTOR_GATE_CAUTION", "ask").lower()
        decision = policy if policy in ("allow", "ask", "deny") else "ask"
        return decision, f"SkillSpector: CAUTION (risk {score}/100)."
    if recommendation == SAFE:
        return "allow", f"SkillSpector: SAFE (risk {score}/100)."
    return "ask", "SkillSpector: inconclusive result; review the source."


def _emit(
    decision: str, reason: str, *, context: str | None = None, system: str | None = None
) -> None:
    out: dict = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }
    if context:
        out["hookSpecificOutput"]["additionalContext"] = context
    if system:
        out["systemMessage"] = system
    print(json.dumps(out))


def _findings_context(report: dict) -> str | None:
    issues = report.get("issues") or []
    if not issues:
        return None
    top = "; ".join(f"{i.get('id')}:{i.get('severity')}" for i in issues[:5])
    return f"SkillSpector top findings: {top}"


def main() -> int:
    event = _read_event()
    if event.get("hook_event_name") != "PreToolUse":
        return 0  # not our event; defer

    target = extract_target(str(event.get("tool_name") or ""), event.get("tool_input") or {})
    if not target:
        return 0  # not a skill fetch we recognise; do not interfere

    status, report = scan(target)
    if status == "no_tool":
        _emit(
            "allow",
            "SkillSpector not installed; install gate skipped.",
            system="SkillSpector gate: `skillspector` not found on PATH — skill not scanned.",
        )
        return 0
    if status == "error" or report is None:
        _emit("ask", f"SkillSpector could not scan {target}; review the source before installing.")
        return 0

    decision, reason = decide(report)
    _emit(decision, reason, context=_findings_context(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
