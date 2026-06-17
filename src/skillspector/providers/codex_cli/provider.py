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

Activated by ``SKILLSPECTOR_PROVIDER=codex_cli``. Authentication is handled by
the ``codex`` CLI's own session (``codex login``); no API key is read or
required.

All behaviour is inherited from
:class:`skillspector.providers._agent_cli_base.AgentCLIProviderBase`; the
"codex"-specific argv (``codex exec --json --sandbox read-only --ephemeral
--ignore-user-config --ignore-rules``; never ``--dangerously-bypass-*``),
output parsing, and auth probe live in the
:mod:`skillspector.providers._agent_cli` registry.
"""

from __future__ import annotations

from pathlib import Path

from skillspector.providers._agent_cli_base import AgentCLIProviderBase

BINARY_NAME = "codex"


class CodexCLIProvider(AgentCLIProviderBase):
    """Codex CLI provider (no API key; uses the local ``codex`` login)."""

    BINARY_NAME = "codex"
    DEFAULT_MODEL = "o4-mini"
    SLOT_DEFAULTS: dict[str, str] = {}
    REGISTRY_PATH = str(Path(__file__).with_name("model_registry.yaml"))
