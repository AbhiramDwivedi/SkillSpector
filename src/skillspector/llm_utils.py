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

"""Shared LLM utilities (OpenAI-compatible chat models + agent CLI transports).

Credentials are resolved in this order:
    1. The active provider (see :mod:`skillspector.providers`):
       - CLI providers (``claude_cli``, ``codex_cli``): use ``is_available()``
         and ``complete()`` — no API key needed.
       - HTTP providers (``anthropic``, ``openai``, ``nv_build``): read their
         respective credential env vars and supply a base URL.
    2. ``OPENAI_API_KEY`` / ``OPENAI_BASE_URL`` (the langchain-openai
       defaults) — only consulted for HTTP providers when the provider's
       own credential env var is unset.

There is no SkillSpector-specific credential env var: setting
``NVIDIA_INFERENCE_KEY`` configures whichever NVIDIA endpoint the
deployment ships with, and any other OpenAI-compatible endpoint is
configured via the standard ``OPENAI_*`` envs.
"""

from __future__ import annotations

import asyncio
import json
import os

from langchain_openai import ChatOpenAI

from skillspector.constants import MODEL_CONFIG
from skillspector.model_info import get_max_input_tokens, get_max_output_tokens
from skillspector.providers import (
    get_active_provider,
    has_cli_capability,
    resolve_provider_credentials,
)


def _resolve_llm_credentials() -> tuple[str, str | None]:
    """Return ``(api_key, base_url)`` resolved from the environment.

    Tries the active provider first; falls back to ``OPENAI_API_KEY``
    / ``OPENAI_BASE_URL`` when the provider is not configured.

    Raises:
        ValueError: when no API key can be resolved from any source.
        RuntimeError: when called for a CLI provider (use ``is_llm_available``
            / ``chat_completion`` directly instead).
    """
    creds = resolve_provider_credentials()
    if creds is not None:
        return creds

    resolved_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not resolved_key:
        raise ValueError(
            "No LLM API key configured. Set the credential env var for the "
            "active provider, or set OPENAI_API_KEY (and optionally "
            "OPENAI_BASE_URL) to use a standard OpenAI-compatible endpoint. "
            "Use --no-llm to skip LLM analysis and run static checks only."
        )

    resolved_base = os.environ.get("OPENAI_BASE_URL", "").strip() or None
    return resolved_key, resolved_base


def is_llm_available() -> tuple[bool, str | None]:
    """Return ``(available, error_message)`` describing LLM availability.

    For CLI providers (``claude_cli``, ``codex_cli``) the check delegates
    to the provider's ``is_available()`` method (binary on PATH + auth).
    For HTTP providers, it falls back to credential resolution.
    """
    provider = get_active_provider()
    if has_cli_capability(provider):
        return provider.is_available()  # type: ignore[attr-defined]
    try:
        _resolve_llm_credentials()
    except ValueError as exc:
        return False, str(exc)
    return True, None


def fetch_model_token_limits(model_label: str) -> tuple[int, int]:
    """Return ``(max_input_tokens, max_output_tokens)`` for *model_label*."""
    return get_max_input_tokens(model_label), get_max_output_tokens(model_label)


# ---------------------------------------------------------------------------
# Agent CLI chat-model adapter
# ---------------------------------------------------------------------------
#
# The LLM analyzers (meta_analyzer, semantic_*) obtain a model from
# ``get_chat_model()`` and call ``.invoke()`` / ``.with_structured_output(
# schema).invoke()`` on it (see ``llm_analyzer_base``) — they never go through
# ``chat_completion``. To support CLI providers there, ``get_chat_model``
# returns this minimal adapter, which mimics the slice of the ``ChatOpenAI``
# interface the analyzers rely on, backed by the provider's ``complete()``
# subprocess transport.


class _AgentCLIMessage:
    """Minimal stand-in for a LangChain message: exposes ``.content``."""

    def __init__(self, content: str) -> None:
        self.content = content


def _extract_json_object(raw: str) -> dict:
    """Extract a single JSON object from a CLI model's text response.

    Tolerates markdown code fences and surrounding prose. Raises ``ValueError``
    (fail-closed) when no JSON object can be parsed.
    """
    text = raw.strip()
    if text.startswith("```"):
        # Drop the opening fence line (``` or ```json) and any closing fence.
        text = text.split("\n", 1)[1] if "\n" in text else ""
        fence = text.rfind("```")
        if fence != -1:
            text = text[:fence]
        text = text.strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            obj = json.loads(text[start : end + 1])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    raise ValueError(f"could not extract a JSON object from CLI response: {raw[:200]!r}")


class _StructuredAgentCLIModel:
    """Mimics ``ChatOpenAI.with_structured_output(schema)`` for a CLI provider.

    ``invoke`` augments the prompt with the schema, calls the provider's
    ``complete()``, then parses and validates the response into *schema*.
    """

    def __init__(self, provider: object, model: str, max_output_tokens: int, schema: type) -> None:
        self._provider = provider
        self._model = model
        self._max_output_tokens = max_output_tokens
        self._schema = schema

    def _augment(self, prompt: str) -> str:
        schema_json = json.dumps(self._schema.model_json_schema(), indent=2)
        return (
            f"{prompt}\n\n"
            "Respond with ONLY a single JSON object conforming to the JSON Schema "
            "below. Do not wrap it in markdown code fences and do not add any prose "
            f"before or after the JSON.\n\nJSON Schema:\n{schema_json}"
        )

    def invoke(self, prompt: str) -> object:
        raw = self._provider.complete(  # type: ignore[attr-defined]
            self._augment(prompt),
            model=self._model,
            max_output_tokens=self._max_output_tokens,
        )
        return self._schema.model_validate(_extract_json_object(raw))

    async def ainvoke(self, prompt: str) -> object:
        return await asyncio.to_thread(self.invoke, prompt)


class AgentCLIChatModel:
    """Minimal ``ChatOpenAI``-compatible adapter backed by a CLI provider.

    Implements only the surface the analyzers use: ``invoke`` (returns an
    object with ``.content``), ``ainvoke``, and ``with_structured_output``.
    """

    def __init__(self, provider: object, model: str, max_output_tokens: int) -> None:
        self._provider = provider
        self._model = model
        self._max_output_tokens = max_output_tokens

    def invoke(self, prompt: str) -> _AgentCLIMessage:
        text = self._provider.complete(  # type: ignore[attr-defined]
            prompt,
            model=self._model,
            max_output_tokens=self._max_output_tokens,
        )
        return _AgentCLIMessage(text)

    async def ainvoke(self, prompt: str) -> _AgentCLIMessage:
        return await asyncio.to_thread(self.invoke, prompt)

    def with_structured_output(self, schema: type) -> _StructuredAgentCLIModel:
        return _StructuredAgentCLIModel(
            self._provider, self._model, self._max_output_tokens, schema
        )


def get_chat_model(model: str | None = None) -> ChatOpenAI | AgentCLIChatModel:
    """Return a chat model for the active provider.

    For CLI providers (``claude_cli``, ``codex_cli``) this returns an
    :class:`AgentCLIChatModel` adapter backed by the provider's ``complete()``
    subprocess transport — so the LLM analyzers (which use ``.invoke()`` and
    ``.with_structured_output()``) work with no API key. For HTTP providers it
    returns a :class:`ChatOpenAI` configured against the resolved endpoint.

    Raises:
        ValueError: when an HTTP provider has no API key configured.
    """
    resolved_model = model or MODEL_CONFIG["default"]

    provider = get_active_provider()
    if has_cli_capability(provider):
        return AgentCLIChatModel(provider, resolved_model, get_max_output_tokens(resolved_model))

    resolved_key, resolved_base = _resolve_llm_credentials()
    return ChatOpenAI(
        model=resolved_model,
        base_url=resolved_base,
        api_key=resolved_key,
        max_tokens=get_max_output_tokens(resolved_model),
        timeout=120,
    )


def chat_completion(prompt: str, *, model: str | None = None) -> str:
    """Request a single chat completion and return the assistant content.

    Routes through :func:`get_chat_model`, which dispatches to the CLI adapter
    for CLI providers and to ``ChatOpenAI`` for HTTP providers.
    """
    response = get_chat_model(model=model).invoke(prompt)
    return response.content or ""
