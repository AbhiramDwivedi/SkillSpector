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

"""Runtime entry point for the install gate: ``python -m skillspector.gate --agent NAME``.

Reads a pre-tool hook event on stdin, and if it is a recognised skill install,
scans the target and writes an allow / ask / deny response in the requested
agent's schema. Anything else produces no output (exit 0) so normal tool calls
proceed untouched.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import evaluate
from .agents import AGENT_NAMES, AGENTS


def _read_event() -> dict:
    try:
        raw = sys.stdin.read()
    except (OSError, ValueError):
        return {}
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m skillspector.gate",
        description="SkillSpector pre-tool install gate.",
    )
    parser.add_argument(
        "--agent",
        choices=AGENT_NAMES,
        default="claude",
        help="Which coding-agent CLI's hook schema to speak (default: claude).",
    )
    args = parser.parse_args(argv)
    agent = AGENTS[args.agent]

    command = agent.parse(_read_event())
    if not command:
        return 0  # not a gateable tool call
    verdict = evaluate(command)
    if verdict is None:
        return 0  # not a skill install; do not interfere
    return agent.emit(verdict)


if __name__ == "__main__":
    sys.exit(main())
