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

"""Agent-agnostic install-gate core for SkillSpector.

Coding-agent CLIs (Claude Code, Codex, Cursor, Gemini) each expose a
pre-tool-execution hook: it runs a command, hands it the pending tool call as
JSON on stdin, and blocks the call when the command answers ``deny``. This
package implements one agent-agnostic gate — it recognises skill/plugin
*install* commands (``git clone``, ``npx``, ``apm``, archive fetches), scans the
target with the ``skillspector`` CLI, and returns an allow / ask / deny verdict.
Per-agent adapters (:mod:`skillspector.gate.agents`) translate each CLI's event
and response schema; installers (:mod:`skillspector.gate.install`) write the
right hook config per CLI.

The core never interpolates the command into a shell string — the untrusted
target is passed to ``skillspector scan`` as a single argv element with
``shell=False`` — so a hostile command cannot inject into the gate's subprocess.

Decision policy (SkillSpector's recommendation maps directly to a decision)::

    SAFE            -> allow
    CAUTION         -> ask    (override via SKILLSPECTOR_GATE_CAUTION=allow|deny)
    DO_NOT_INSTALL  -> deny

Failure modes are conservative but non-disruptive::

    skillspector CLI not on PATH   -> allow + warning (do not break workflows)
    scan failed / unparseable      -> ask (fail toward human review)
    install not directly scannable -> ask (surface for review; e.g. bare npx pkg)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass

SAFE = "SAFE"
CAUTION = "CAUTION"
DO_NOT_INSTALL = "DO_NOT_INSTALL"

SCAN_TIMEOUT_SECONDS = 120

# ── Install-command detection ─────────────────────────────────────────────
# Patterns are anchored to a fetch/install verb and use bounded character
# classes (no nested quantifiers) so they cannot catastrophically backtrack.

# `git clone [opts] <url> [dir]` — first http(s)/git URL argument.
_GIT_CLONE = re.compile(
    r"\bgit\s+clone\b[^\n]*?\s(?P<url>(?:https?://|git://|git@)\S+)",
    re.IGNORECASE,
)
# Direct fetch of a skill archive (curl/wget <url>.zip|.tar.gz|.tgz|...).
_ARCHIVE_URL = re.compile(
    r"(?P<url>https?://\S+\.(?:zip|tar\.gz|tgz|tar\.bz2|tar))\b",
    re.IGNORECASE,
)
# `apm install owner/repo[#ref]` / `npx owner/repo` — a GitHub-style slug we can
# map to a scannable repo URL. Captures owner/repo, ignoring flags in between.
_REPO_SLUG = re.compile(
    r"\b(?:apm\s+install|npx(?:\s+(?:-y|--yes|-p\s+\S+))*)\s+"
    r"(?:github:)?(?P<slug>[\w.-]+/[\w.-]+)\b",
    re.IGNORECASE,
)
# Any npx / apm install invocation (used to flag un-scannable package installs
# for human review when no repo slug/URL is present).
_PKG_INSTALL = re.compile(
    r"\b(?:npx\s+(?:-y\s+|--yes\s+|-p\s+\S+\s+)*(?P<npx>@?[\w./-]+)"
    r"|apm\s+install\s+(?P<apm>@?[\w./-]+))",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Target:
    """A detected install target.

    ``kind`` is ``"scan"`` when :data:`value` is a URL/path the ``skillspector``
    CLI can scan directly, or ``"review"`` when an install was detected but is
    not directly scannable (e.g. a bare ``npx`` package) and should be surfaced
    for human review.
    """

    kind: str
    value: str


def extract_install_target(command: str) -> Target | None:
    """Return the skill-install :class:`Target` in *command*, or ``None``.

    Recognises ``git clone`` URLs, ``.zip``/``.tar`` archive fetches, and
    ``apm``/``npx`` installs. GitHub-style ``owner/repo`` slugs map to a
    scannable ``https://github.com/owner/repo`` URL; a bare package name yields a
    ``"review"`` target (SkillSpector cannot pre-scan an arbitrary registry
    package). Unrelated commands return ``None`` so the gate never interferes.
    """
    git = _GIT_CLONE.search(command)
    if git:
        return Target("scan", git.group("url"))
    archive = _ARCHIVE_URL.search(command)
    if archive:
        return Target("scan", archive.group("url"))
    slug = _REPO_SLUG.search(command)
    if slug:
        return Target("scan", f"https://github.com/{slug.group('slug')}")
    pkg = _PKG_INSTALL.search(command)
    if pkg:
        return Target("review", pkg.group("npx") or pkg.group("apm"))
    return None


def scan(target: str) -> tuple[str, dict | None]:
    """Run ``skillspector scan`` on *target*; return ``(status, report)``.

    ``status`` is ``"ok"`` (report parsed), ``"no_tool"`` (CLI not on PATH), or
    ``"error"`` (scan failed / unparseable).
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
    """Map a SkillSpector report to a ``(decision, reason)`` pair.

    ``decision`` is one of ``"allow"`` / ``"ask"`` / ``"deny"`` — the normalized
    verdict every per-agent adapter translates into that CLI's response shape.
    """
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


def findings_context(report: dict) -> str | None:
    """Summarise the top findings (id:severity) for the agent's context, if any."""
    issues = report.get("issues") or []
    if not issues:
        return None
    top = "; ".join(f"{i.get('id')}:{i.get('severity')}" for i in issues[:5])
    return f"SkillSpector top findings: {top}"


@dataclass(frozen=True)
class Verdict:
    """Normalized gate verdict produced by :func:`evaluate` and rendered by adapters."""

    decision: str  # "allow" | "ask" | "deny"
    reason: str
    context: str | None = None
    system: str | None = None


def evaluate(command: str) -> Verdict | None:
    """Run the full gate over a Bash *command*; return a :class:`Verdict` or ``None``.

    Returns ``None`` when *command* is not a recognised skill install, so the
    caller emits nothing and the tool call proceeds untouched.
    """
    target = extract_install_target(command)
    if target is None:
        return None
    if target.kind == "review":
        return Verdict(
            "ask",
            f"SkillSpector cannot pre-scan package install '{target.value}'; "
            "review the source before installing.",
        )
    status, report = scan(target.value)
    if status == "no_tool":
        return Verdict(
            "allow",
            "SkillSpector not installed; install gate skipped.",
            system="SkillSpector gate: `skillspector` not found on PATH — skill not scanned.",
        )
    if status == "error" or report is None:
        return Verdict(
            "ask",
            f"SkillSpector could not scan {target.value}; review the source before installing.",
        )
    decision, reason = decide(report)
    return Verdict(decision, reason, context=findings_context(report))
