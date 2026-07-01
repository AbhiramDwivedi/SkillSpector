# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""SkillSpector PreToolUse gate for Claude Code (self-contained plugin script).

Reads a Claude Code PreToolUse hook event on stdin. When the agent's tool call
installs a skill from a *scannable* source (a ``git clone`` URL, a ``.zip``/
``.tar`` archive URL, or an ``apm``/``npx`` GitHub ``owner/repo`` slug), it scans
the target with ``skillspector scan`` and returns an ``allow`` / ``ask`` / ``deny``
decision from the risk recommendation. A non-scannable package install (a bare
``npx``/``apm`` package) is surfaced for review (``ask``). Anything else is left
alone so normal commands are unaffected.

This script is intentionally **self-contained** — it depends only on the
``skillspector`` CLI being on ``PATH`` (invoked as a subprocess), never on the
``skillspector`` Python package being importable — so the marketplace plugin
works no matter how the scanner was installed (pip, pipx, uv, …). Its detection
mirrors :mod:`skillspector.gate` (the packaged multi-agent gate); a consistency
test keeps the two in lock-step.

Decision policy (recommendation maps directly to a decision)::

    SAFE            -> allow
    CAUTION         -> ask    (override via SKILLSPECTOR_GATE_CAUTION=allow|deny)
    DO_NOT_INSTALL  -> deny

Failure modes::

    skillspector not on PATH        -> allow + a warning (do not break workflows)
    scan ran but failed/unparseable -> ask (fail toward review)
    non-scannable package install   -> ask (surface for review)

Security: the extracted target is passed to ``skillspector scan`` as an argv
element with ``shell=False`` — it is never interpolated into a shell string, so a
hostile command/URL cannot inject anything into the gate's own subprocess.

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

# Detection mirrors skillspector.gate.extract_install_target (kept in sync by
# tests/unit/test_claude_gate.py::TestConsistencyWithPackage).
_GIT_CLONE = re.compile(
    r"\bgit\s+clone\b[^\n]*?\s(?P<url>(?:https?://|git://|git@)\S+)",
    re.IGNORECASE,
)
_ARCHIVE_URL = re.compile(
    r"(?P<url>https?://\S+\.(?:zip|tar\.gz|tgz|tar\.bz2|tar))\b",
    re.IGNORECASE,
)
_REPO_SLUG = re.compile(
    r"\b(?:apm\s+install|npx(?:\s+(?:-y|--yes|-p\s+\S+))*)\s+"
    r"(?:github:)?(?P<slug>[\w.-]+/[\w.-]+)\b",
    re.IGNORECASE,
)
_PKG_INSTALL = re.compile(
    r"\b(?:npx\s+(?:-y\s+|--yes\s+|-p\s+\S+\s+)*(?P<npx>@?[\w./-]+)"
    r"|apm\s+install\s+(?P<apm>@?[\w./-]+))",
    re.IGNORECASE,
)


def _read_event() -> dict:
    try:
        return json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        return {}


def extract_target(tool_name: str, tool_input: dict) -> str | None:
    """Return a scannable target URL if the tool call fetches a skill, else None.

    Recognises ``git clone`` URLs, ``.zip``/``.tar`` archive URLs, and
    ``apm``/``npx`` GitHub ``owner/repo`` slugs (mapped to a repo URL) — all of
    which ``skillspector scan`` accepts. A bare package install is not returned
    here (it is not directly scannable); see :func:`unscannable_install`.
    """
    if tool_name != "Bash":
        return None
    command = str(tool_input.get("command") or "")
    git = _GIT_CLONE.search(command)
    if git:
        return git.group("url")
    archive = _ARCHIVE_URL.search(command)
    if archive:
        return archive.group("url")
    slug = _REPO_SLUG.search(command)
    if slug:
        return f"https://github.com/{slug.group('slug')}"
    return None


def unscannable_install(tool_name: str, tool_input: dict) -> str | None:
    """Return a package name for an npx/apm install with no scannable slug, else None."""
    if tool_name != "Bash":
        return None
    command = str(tool_input.get("command") or "")
    if _GIT_CLONE.search(command) or _ARCHIVE_URL.search(command) or _REPO_SLUG.search(command):
        return None
    pkg = _PKG_INSTALL.search(command)
    return (pkg.group("npx") or pkg.group("apm")) if pkg else None


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

    tool_name = str(event.get("tool_name") or "")
    tool_input = event.get("tool_input") or {}

    target = extract_target(tool_name, tool_input)
    if target is None:
        package = unscannable_install(tool_name, tool_input)
        if package is None:
            return 0  # not a skill fetch we recognise; do not interfere
        _emit(
            "ask",
            f"SkillSpector cannot pre-scan package install '{package}'; "
            "review the source before installing.",
        )
        return 0

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
