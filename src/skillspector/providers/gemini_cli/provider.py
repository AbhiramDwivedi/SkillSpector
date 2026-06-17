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

"""Gemini CLI provider — Stage-2 LLM analysis via the local ``gemini`` binary.

**EXPERIMENTAL / UNVERIFIED.** This provider was written without a ``gemini``
CLI to test against. The gemini-specific flags (see ``_build_gemini_argv`` in
:mod:`skillspector.providers._agent_cli`) and the model names below are
``TODO(verify)`` against the real Gemini CLI. Until verified, a wrong flag only
makes the CLI fail closed (non-zero exit / unparseable output) — it cannot
weaken the security model.

Activated by ``SKILLSPECTOR_PROVIDER=gemini_cli``. All behaviour is inherited
from :class:`skillspector.providers._agent_cli_base.AgentCLIProviderBase`.
"""

from __future__ import annotations

from pathlib import Path

from skillspector.providers._agent_cli_base import AgentCLIProviderBase

BINARY_NAME = "gemini"


class GeminiCLIProvider(AgentCLIProviderBase):
    """Gemini CLI provider (EXPERIMENTAL; no API key; uses the local gemini login)."""

    BINARY_NAME = "gemini"
    DEFAULT_MODEL = "gemini-2.5-pro"  # TODO(verify): real model id
    SLOT_DEFAULTS = {"meta_analyzer": "gemini-2.5-flash"}  # TODO(verify)
    REGISTRY_PATH = str(Path(__file__).with_name("model_registry.yaml"))
