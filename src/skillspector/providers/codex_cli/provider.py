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

"""Codex CLI provider — Stage-2 LLM analysis via the local ``codex`` binary.

Activated by ``SKILLSPECTOR_PROVIDER=codex_cli``.

Authentication is handled entirely by the ``codex`` CLI's own session
(``codex login``).  No API key is read or required by SkillSpector.

This provider uses the same hardened subprocess helper as
:mod:`skillspector.providers.claude_cli.provider` —
:func:`skillspector.providers._agent_cli.run_agent_cli` — which enforces
no-shell, stdin-only content, capability stripping, env scrubbing, timeout,
and fail-closed error handling.

Sandbox flags used with ``codex exec``:
- ``--sandbox read-only``   Most restrictive mode; no code execution.
- ``--ephemeral``           No session persistence.
- ``--ignore-user-config``  Ignore ``$CODEX_HOME/config.toml``.
- ``--ignore-rules``        Skip user/project execpolicy rules.
- ``--json``                Structured JSONL output for deterministic parsing.

Deliberately NOT used:
- ``--dangerously-bypass-approvals-and-sandbox`` — explicitly forbidden.
- ``--dangerously-bypass-hook-trust`` — explicitly forbidden.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from skillspector.providers import registry
from skillspector.providers._agent_cli import find_binary, run_agent_cli

BINARY_NAME = "codex"
REGISTRY_PATH = str(Path(__file__).with_name("model_registry.yaml"))

# NOTE: the prompt is sent to the CLI unchanged (parity with the HTTP path).
# Prompt-layer content hardening belongs in the meta_analyzer, not this
# transport. Security here comes from the read-only sandbox argv.


class CodexCLIProvider:
    """Codex CLI credentials + metadata + subprocess transport.

    Implements the same interface as :class:`~skillspector.providers.claude_cli.provider.ClaudeCLIProvider`.
    """

    DEFAULT_MODEL = "o4-mini"
    SLOT_DEFAULTS: dict[str, str] = {}

    # -- Credentials ---------------------------------------------------------

    def resolve_credentials(self) -> tuple[str, str | None] | None:
        """No HTTP credentials needed — the CLI handles auth itself."""
        return None

    # -- Availability --------------------------------------------------------

    def is_available(self) -> tuple[bool, str | None]:
        """Return ``(True, None)`` when the ``codex`` binary is present AND a
        login session exists.

        Runs ``codex login status`` (a local check — no inference) so a report's
        ``llm_available`` does not claim availability when the CLI is not logged
        in. Returns ``(False, reason)`` when the binary is missing, the check
        fails, or no session is logged in.
        """
        binary = find_binary(BINARY_NAME)
        if binary is None:
            return False, f"{BINARY_NAME!r} binary not found on PATH"
        try:
            result = subprocess.run(
                [binary, "login", "status"],
                capture_output=True,
                shell=False,
                timeout=15,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            return False, f"{BINARY_NAME} login status check failed: {exc}"
        out = (result.stdout or b"").decode("utf-8", errors="replace").lower()
        if result.returncode != 0 or "not logged in" in out:
            return False, f"{BINARY_NAME} is not authenticated (run `codex login`)"
        return True, None

    # -- Transport -----------------------------------------------------------

    def complete(self, prompt: str, *, model: str, max_output_tokens: int = 8192) -> str:
        """Invoke the local ``codex`` CLI and return the assistant text.

        Args:
            prompt:           The full prompt built by the analyzer.
            model:            Model label (e.g. ``"o4-mini"``).
            max_output_tokens: Currently unused for codex (no equivalent flag).

        Returns:
            The assistant's text response as a plain string.

        Raises:
            AgentCLIError: on any failure.
        """
        return run_agent_cli(
            BINARY_NAME,
            prompt,
            model=model,
            max_output_tokens=max_output_tokens,
        )

    # -- Metadata ------------------------------------------------------------

    def get_context_length(self, model: str) -> int | None:
        return registry.lookup_context_length(REGISTRY_PATH, model)

    def get_max_output_tokens(self, model: str) -> int | None:
        return registry.lookup_max_output_tokens(REGISTRY_PATH, model)

    def resolve_model(self, slot: str = "default") -> str:
        """Resolve model: ``SKILLSPECTOR_MODEL`` env > slot default > ``DEFAULT_MODEL``."""
        user_input = os.environ.get("SKILLSPECTOR_MODEL", "").strip()
        return user_input or self.SLOT_DEFAULTS.get(slot, "") or self.DEFAULT_MODEL
