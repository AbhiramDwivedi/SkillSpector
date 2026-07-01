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

"""Per-agent hook adapters.

Every supported CLI exposes the same shape of pre-tool hook — a command that
receives the pending tool call as JSON on stdin and blocks it by answering
``deny`` — but the event and response *schemas* differ. Each :class:`Agent` here
provides two thin translators: :func:`Agent.parse` pulls the shell command out of
that CLI's event, and :func:`Agent.emit` renders a normalized
:class:`~skillspector.gate.Verdict` into that CLI's response JSON. The scanning
logic lives once in the core; these adapters are pure schema translation.

Response contracts (as of the CLI versions researched)::

    Claude Code / Codex : {"hookSpecificOutput": {"permissionDecision": ...}}
    Cursor              : {"permission": "allow"|"ask"|"deny", ...}
    Gemini              : {"decision": "deny", "reason": ...}   (no interactive "ask")

All four also honour a bare exit code 2 as "deny", used as the universal fallback.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

from . import Verdict


def _command_from_tool_input(event: dict) -> str | None:
    """Extract ``tool_input.command`` (Claude/Codex/Gemini shape)."""
    tool_input = event.get("tool_input") or {}
    command = tool_input.get("command")
    return str(command) if command else None


# ── parse: CLI event -> shell command (or None to stay out of the way) ────


def _parse_tool_call(event: dict, shell_tools: tuple[str, ...]) -> str | None:
    if event.get("tool_name") not in shell_tools:
        return None
    return _command_from_tool_input(event)


def _parse_claude(event: dict) -> str | None:
    # Claude Code & Codex PreToolUse: {tool_name: "Bash", tool_input: {command}}
    return _parse_tool_call(event, ("Bash",))


def _parse_gemini(event: dict) -> str | None:
    # Gemini BeforeTool: shell tool is `run_shell_command`.
    return _parse_tool_call(event, ("run_shell_command", "Shell", "Bash"))


def _parse_cursor(event: dict) -> str | None:
    # Cursor beforeShellExecution puts the command at the top level; preToolUse
    # uses the tool_input shape — support both.
    command = event.get("command")
    if command:
        return str(command)
    return _command_from_tool_input(event)


# ── emit: normalized Verdict -> CLI response JSON (returns process exit code) ──


def _emit_claude(verdict: Verdict) -> int:
    output: dict = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": verdict.decision,
            "permissionDecisionReason": verdict.reason,
        }
    }
    if verdict.context:
        output["hookSpecificOutput"]["additionalContext"] = verdict.context
    if verdict.system:
        output["systemMessage"] = verdict.system
    print(json.dumps(output))
    return 0


def _emit_cursor(verdict: Verdict) -> int:
    print(
        json.dumps(
            {
                "permission": verdict.decision,
                "agent_message": verdict.reason,
                "user_message": verdict.reason,
            }
        )
    )
    return 0


def _emit_gemini(verdict: Verdict) -> int:
    # Gemini hooks express allow (silent) or deny; there is no interactive "ask".
    # Fail safe: a CAUTION "ask" becomes deny with a self-documenting reason
    # (users can opt out with SKILLSPECTOR_GATE_CAUTION=allow).
    if verdict.decision == "allow":
        return 0  # stay silent so we don't override the agent's allow-list
    reason = verdict.reason
    if verdict.decision == "ask":
        reason = (
            f"{reason} (blocked: Gemini has no interactive confirmation for hooks; "
            "set SKILLSPECTOR_GATE_CAUTION=allow to permit)"
        )
    print(json.dumps({"decision": "deny", "reason": reason}))
    return 0


@dataclass(frozen=True)
class Agent:
    """A CLI adapter: schema translation for one coding-agent's pre-tool hook."""

    name: str
    parse: Callable[[dict], str | None]
    emit: Callable[[Verdict], int]


AGENTS: dict[str, Agent] = {
    "claude": Agent("claude", _parse_claude, _emit_claude),
    # Codex clones Claude Code's PreToolUse contract (identical field names).
    "codex": Agent("codex", _parse_claude, _emit_claude),
    "cursor": Agent("cursor", _parse_cursor, _emit_cursor),
    "gemini": Agent("gemini", _parse_gemini, _emit_gemini),
}

AGENT_NAMES = tuple(AGENTS)
