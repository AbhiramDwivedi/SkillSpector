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

"""Install the SkillSpector gate hook into each supported CLI's config.

Every installer is idempotent (re-running is a no-op) and writes a hook that
invokes ``<python> -m skillspector.gate --agent <name>`` — using the interpreter
that ran the installer, so the ``skillspector`` package is guaranteed importable
by the hook regardless of how the CLI itself resolves ``python``.
"""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path

_MARKER = "skillspector.gate"  # idempotency sentinel: our command always contains it
_TIMEOUT = 130
_STATUS = "SkillSpector: scanning skill before install..."

# Result codes returned alongside the written path.
INSTALLED = "installed"
ALREADY = "already"


class UnsupportedAgentError(ValueError):
    """Raised for an agent name with no installer."""


def default_config_path(agent: str) -> Path:
    """Return the default per-user config path for *agent*."""
    home = Path.home()
    paths = {
        "claude": home / ".claude" / "settings.json",
        "codex": home / ".codex" / "config.toml",
        "cursor": home / ".cursor" / "hooks.json",
        "gemini": home / ".gemini" / "settings.json",
    }
    if agent not in paths:
        raise UnsupportedAgentError(agent)
    return paths[agent]


def _hook_command(agent: str, python: str) -> str:
    return f'"{python}" -m skillspector.gate --agent {agent}'


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"could not read {path}: {exc}") from exc
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _json_contains_marker(obj: object) -> bool:
    """True if any ``command`` string anywhere in *obj* is our gate command."""
    if isinstance(obj, dict):
        cmd = obj.get("command")
        if isinstance(cmd, str) and _MARKER in cmd:
            return True
        return any(_json_contains_marker(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_json_contains_marker(v) for v in obj)
    return False


def _install_claude(path: Path, python: str) -> str:
    settings = _load_json(path)
    pre = settings.setdefault("hooks", {}).setdefault("PreToolUse", [])
    if _json_contains_marker(pre):
        return ALREADY
    pre.append(
        {
            "matcher": "Bash",
            "hooks": [
                {
                    "type": "command",
                    "command": _hook_command("claude", python),
                    "timeout": _TIMEOUT,
                    "statusMessage": _STATUS,
                }
            ],
        }
    )
    _write_json(path, settings)
    return INSTALLED


def _install_gemini(path: Path, python: str) -> str:
    settings = _load_json(path)
    before = settings.setdefault("hooks", {}).setdefault("BeforeTool", [])
    if _json_contains_marker(before):
        return ALREADY
    before.append(
        {
            "matcher": "run_shell_command|Shell|Bash",
            "hooks": [
                {
                    "name": "skillspector-gate",
                    "type": "command",
                    "command": _hook_command("gemini", python),
                    "timeout": _TIMEOUT,
                }
            ],
        }
    )
    _write_json(path, settings)
    return INSTALLED


def _install_cursor(path: Path, python: str) -> str:
    config = _load_json(path)
    config.setdefault("version", 1)
    before = config.setdefault("hooks", {}).setdefault("beforeShellExecution", [])
    if _json_contains_marker(before):
        return ALREADY
    before.append({"command": _hook_command("cursor", python)})
    _write_json(path, config)
    return INSTALLED


_CODEX_BLOCK = """
# --- SkillSpector install gate (added by `skillspector install-hook`) ---
[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = '{command}'
timeout = {timeout}
"""


def _install_codex(path: Path, python: str) -> str:
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    if _MARKER in existing:
        return ALREADY
    if existing.strip():
        # Fail loudly rather than corrupt a config we cannot parse.
        tomllib.loads(existing)
    block = _CODEX_BLOCK.format(command=_hook_command("codex", python), timeout=_TIMEOUT)
    path.parent.mkdir(parents=True, exist_ok=True)
    separator = "" if existing.endswith("\n") or not existing else "\n"
    path.write_text(existing + separator + block, encoding="utf-8")
    return INSTALLED


_INSTALLERS = {
    "claude": _install_claude,
    "codex": _install_codex,
    "cursor": _install_cursor,
    "gemini": _install_gemini,
}

INSTALLABLE_AGENTS = tuple(_INSTALLERS)


def install(
    agent: str, config_path: Path | None = None, python: str | None = None
) -> tuple[Path, str]:
    """Install the gate hook for *agent*. Returns ``(path, INSTALLED|ALREADY)``.

    Idempotent: an existing SkillSpector gate entry is left untouched.
    """
    if agent not in _INSTALLERS:
        raise UnsupportedAgentError(agent)
    path = config_path or default_config_path(agent)
    result = _INSTALLERS[agent](path, python or sys.executable)
    return path, result
