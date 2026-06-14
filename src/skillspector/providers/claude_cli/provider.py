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

"""Claude CLI provider — Stage-2 LLM analysis via the local ``claude`` binary.

Activated by ``SKILLSPECTOR_PROVIDER=claude_cli``.

Authentication is handled entirely by the ``claude`` CLI's own OAuth /
keychain session (``claude auth login``).  No API key is read or
required by SkillSpector.

This provider implements the optional ``complete()`` and ``is_available()``
extension methods defined in :mod:`skillspector.providers.base` so that
:func:`skillspector.llm_utils.chat_completion` dispatches to the CLI
transport instead of ``ChatOpenAI``.

Security:
    All subprocess invocations go through
    :func:`skillspector.providers._agent_cli.run_agent_cli` which enforces
    no-shell, stdin-only untrusted content, capability stripping, env
    scrubbing, timeout, and fail-closed error handling.  The prompt is
    passed through unchanged (parity with the HTTP path); security comes
    from the capability-stripped CLI invocation, not from prompt wrapping.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from skillspector.providers import registry
from skillspector.providers._agent_cli import find_binary, run_agent_cli

BINARY_NAME = "claude"
REGISTRY_PATH = str(Path(__file__).with_name("model_registry.yaml"))

# NOTE: the prompt is sent to the CLI unchanged (parity with the HTTP path).
# Prompt-layer content hardening belongs in the meta_analyzer (which frames the
# untrusted content), not in this transport. Security here comes from the
# capability-stripped argv (see _build_claude_argv).


class ClaudeCLIProvider:
    """Claude CLI credentials + bundled-YAML metadata + subprocess transport.

    Implements:
      - ``resolve_credentials()`` — always returns ``None`` (no HTTP creds needed).
      - ``is_available() -> tuple[bool, str | None]`` — checks binary on PATH
        and that it can answer basic queries (auth check via ``--version``).
      - ``complete(prompt, *, model, max_output_tokens) -> str`` — invokes the
        hardened subprocess helper.
      - ``get_context_length / get_max_output_tokens / resolve_model`` — standard
        metadata interface backed by bundled YAML.
    """

    DEFAULT_MODEL = "claude-sonnet-4-6"
    SLOT_DEFAULTS: dict[str, str] = {
        "meta_analyzer": "claude-haiku-3-5",
    }

    # -- Credentials ---------------------------------------------------------

    def resolve_credentials(self) -> tuple[str, str | None] | None:
        """No HTTP credentials needed — the CLI handles auth itself."""
        return None

    # -- Availability --------------------------------------------------------

    def is_available(self) -> tuple[bool, str | None]:
        """Return ``(True, None)`` when the ``claude`` binary is present AND an
        authenticated session exists.

        Runs ``claude auth status`` (a local check — no inference) and parses
        the ``loggedIn`` flag, so a report's ``llm_available`` does not claim
        availability when the CLI is not logged in. Returns ``(False, reason)``
        when the binary is missing, the check fails/hangs, or no session is
        logged in. Called once per scan; the cost is negligible next to the
        scan's own LLM calls.
        """
        binary = find_binary(BINARY_NAME)
        if binary is None:
            return False, f"{BINARY_NAME!r} binary not found on PATH"
        try:
            result = subprocess.run(
                [binary, "auth", "status"],
                capture_output=True,
                shell=False,
                timeout=15,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            return False, f"{BINARY_NAME} auth status check failed: {exc}"
        out = (result.stdout or b"").decode("utf-8", errors="replace").strip()
        try:
            logged_in = bool(json.loads(out).get("loggedIn"))
        except (json.JSONDecodeError, AttributeError):
            # Fall back to exit code + text heuristic if output is not JSON.
            logged_in = result.returncode == 0 and "not logged in" not in out.lower()
        if result.returncode != 0 or not logged_in:
            return False, f"{BINARY_NAME} is not authenticated (run `claude auth login`)"
        return True, None

    # -- Transport -----------------------------------------------------------

    def complete(self, prompt: str, *, model: str, max_output_tokens: int = 8192) -> str:
        """Invoke the local ``claude`` CLI and return the assistant text.

        The prompt is passed through unchanged (parity with the HTTP
        ``chat_completion`` path): re-wrapping the analyzer's task prompt as
        "untrusted data" would bury the task and the model would stop following
        it. Security comes from the capability-stripped CLI invocation
        (see ``_build_claude_argv``); content-level prompt hardening is the
        meta_analyzer's responsibility.

        Args:
            prompt:           The full prompt built by the analyzer (may
                              contain untrusted skill content).
            model:            Claude model label (e.g. ``"claude-sonnet-4-6"``).
            max_output_tokens: Passed through to the CLI invocation helper.

        Returns:
            The assistant's text response as a plain string.

        Raises:
            AgentCLIError: on any failure (propagated from
                :func:`~skillspector.providers._agent_cli.run_agent_cli`).
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
