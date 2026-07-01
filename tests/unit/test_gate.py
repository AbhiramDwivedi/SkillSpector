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

"""Tests for the packaged multi-agent install gate (skillspector.gate)."""

from __future__ import annotations

import io
import json
import tomllib

import pytest

from skillspector import gate
from skillspector.gate import Target, Verdict
from skillspector.gate import __main__ as gate_main
from skillspector.gate import agents as gate_agents
from skillspector.gate import install as gate_install


class TestExtractInstallTarget:
    def test_git_clone(self) -> None:
        assert gate.extract_install_target("git clone https://github.com/x/y.git dst") == Target(
            "scan", "https://github.com/x/y.git"
        )

    def test_git_at_ssh(self) -> None:
        t = gate.extract_install_target("git clone git@github.com:x/y.git")
        assert t == Target("scan", "git@github.com:x/y.git")

    def test_zip_archive(self) -> None:
        assert gate.extract_install_target("curl -O https://e.com/skill.zip") == Target(
            "scan", "https://e.com/skill.zip"
        )

    def test_targz_archive(self) -> None:
        assert gate.extract_install_target("wget https://e.com/s.tar.gz") == Target(
            "scan", "https://e.com/s.tar.gz"
        )

    def test_apm_repo_slug_maps_to_github(self) -> None:
        assert gate.extract_install_target("apm install owner/repo") == Target(
            "scan", "https://github.com/owner/repo"
        )

    def test_npx_repo_slug_maps_to_github(self) -> None:
        assert gate.extract_install_target("npx -y owner/repo") == Target(
            "scan", "https://github.com/owner/repo"
        )

    def test_bare_npx_is_review(self) -> None:
        assert gate.extract_install_target("npx create-app") == Target("review", "create-app")

    def test_bare_apm_is_review(self) -> None:
        assert gate.extract_install_target("apm install lonelypkg") == Target("review", "lonelypkg")

    def test_unrelated_command_none(self) -> None:
        assert gate.extract_install_target("ls -la /tmp") is None
        assert gate.extract_install_target("npm run build") is None


class TestDecide:
    def test_safe_allows(self) -> None:
        assert (
            gate.decide({"risk_assessment": {"recommendation": "SAFE", "score": 3}})[0] == "allow"
        )

    def test_do_not_install_denies(self) -> None:
        assert (
            gate.decide({"risk_assessment": {"recommendation": "DO_NOT_INSTALL", "score": 90}})[0]
            == "deny"
        )

    def test_caution_asks(self) -> None:
        assert (
            gate.decide({"risk_assessment": {"recommendation": "CAUTION", "score": 40}})[0] == "ask"
        )

    def test_caution_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SKILLSPECTOR_GATE_CAUTION", "deny")
        assert gate.decide({"risk_assessment": {"recommendation": "CAUTION"}})[0] == "deny"

    def test_unknown_asks(self) -> None:
        assert gate.decide({"risk_assessment": {}})[0] == "ask"


class TestEvaluate:
    def test_unrelated_returns_none(self) -> None:
        assert gate.evaluate("echo hi") is None

    def test_bare_package_review_asks(self) -> None:
        verdict = gate.evaluate("npx create-app")
        assert verdict is not None and verdict.decision == "ask"

    def test_high_risk_denies_with_context(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            gate,
            "scan",
            lambda _t: (
                "ok",
                {
                    "risk_assessment": {"recommendation": "DO_NOT_INSTALL", "score": 95},
                    "issues": [{"id": "P5", "severity": "CRITICAL"}],
                },
            ),
        )
        verdict = gate.evaluate("git clone https://e.com/evil")
        assert verdict is not None
        assert verdict.decision == "deny"
        assert "P5" in (verdict.context or "")

    def test_no_tool_allows_with_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(gate, "scan", lambda _t: ("no_tool", None))
        verdict = gate.evaluate("git clone https://e.com/x")
        assert verdict is not None and verdict.decision == "allow" and verdict.system

    def test_scan_error_asks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(gate, "scan", lambda _t: ("error", None))
        verdict = gate.evaluate("git clone https://e.com/x")
        assert verdict is not None and verdict.decision == "ask"


class TestScanSubprocessSafety:
    def test_target_passed_as_argv_not_shell(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(gate.shutil, "which", lambda _name: "/usr/bin/skillspector")
        captured: dict = {}

        def _fake_run(argv, **kwargs):
            captured["argv"] = argv
            captured["shell"] = kwargs.get("shell")

            class _R:
                returncode = 0
                stdout = "{}"

            return _R()

        monkeypatch.setattr(gate.subprocess, "run", _fake_run)
        gate.scan("https://evil.example/x; rm -rf /")
        assert captured["shell"] is False
        assert "https://evil.example/x; rm -rf /" in captured["argv"]


class TestAdapters:
    def test_claude_parse_bash(self) -> None:
        cmd = gate_agents.AGENTS["claude"].parse(
            {"tool_name": "Bash", "tool_input": {"command": "git clone x"}}
        )
        assert cmd == "git clone x"

    def test_claude_parse_non_bash_none(self) -> None:
        assert gate_agents.AGENTS["claude"].parse({"tool_name": "Read"}) is None

    def test_gemini_parse_shell_tool(self) -> None:
        cmd = gate_agents.AGENTS["gemini"].parse(
            {"tool_name": "run_shell_command", "tool_input": {"command": "x"}}
        )
        assert cmd == "x"

    def test_cursor_parse_top_level_command(self) -> None:
        assert gate_agents.AGENTS["cursor"].parse({"command": "x"}) == "x"

    def test_claude_emit_deny(self, capsys: pytest.CaptureFixture) -> None:
        gate_agents.AGENTS["claude"].emit(Verdict("deny", "reason", context="ctx"))
        out = json.loads(capsys.readouterr().out)
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert out["hookSpecificOutput"]["additionalContext"] == "ctx"

    def test_codex_uses_claude_shape(self, capsys: pytest.CaptureFixture) -> None:
        gate_agents.AGENTS["codex"].emit(Verdict("deny", "reason"))
        out = json.loads(capsys.readouterr().out)
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_cursor_emit(self, capsys: pytest.CaptureFixture) -> None:
        gate_agents.AGENTS["cursor"].emit(Verdict("deny", "reason"))
        out = json.loads(capsys.readouterr().out)
        assert out["permission"] == "deny"

    def test_gemini_emit_deny(self, capsys: pytest.CaptureFixture) -> None:
        gate_agents.AGENTS["gemini"].emit(Verdict("deny", "reason"))
        out = json.loads(capsys.readouterr().out)
        assert out["decision"] == "deny"

    def test_gemini_ask_becomes_deny(self, capsys: pytest.CaptureFixture) -> None:
        gate_agents.AGENTS["gemini"].emit(Verdict("ask", "reason"))
        out = json.loads(capsys.readouterr().out)
        assert out["decision"] == "deny"
        assert "SKILLSPECTOR_GATE_CAUTION" in out["reason"]

    def test_gemini_allow_is_silent(self, capsys: pytest.CaptureFixture) -> None:
        gate_agents.AGENTS["gemini"].emit(Verdict("allow", "reason"))
        assert capsys.readouterr().out.strip() == ""


class TestInstall:
    def test_claude_install_and_idempotent(self, tmp_path) -> None:
        path = tmp_path / "settings.json"
        _, result = gate_install.install("claude", path, python="/usr/bin/python3")
        assert result == gate_install.INSTALLED
        data = json.loads(path.read_text())
        commands = [h["command"] for e in data["hooks"]["PreToolUse"] for h in e["hooks"]]
        assert any("skillspector.gate --agent claude" in c for c in commands)
        # Second run is a no-op.
        _, result2 = gate_install.install("claude", path, python="/usr/bin/python3")
        assert result2 == gate_install.ALREADY
        data2 = json.loads(path.read_text())
        assert len(data2["hooks"]["PreToolUse"]) == 1

    def test_claude_preserves_existing_settings(self, tmp_path) -> None:
        path = tmp_path / "settings.json"
        path.write_text(json.dumps({"model": "opus", "hooks": {"PreToolUse": []}}))
        gate_install.install("claude", path, python="py")
        data = json.loads(path.read_text())
        assert data["model"] == "opus"

    def test_codex_toml(self, tmp_path) -> None:
        path = tmp_path / "config.toml"
        _, result = gate_install.install("codex", path, python="py")
        assert result == gate_install.INSTALLED
        parsed = tomllib.loads(path.read_text())
        cmd = parsed["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        assert "skillspector.gate --agent codex" in cmd

    def test_codex_idempotent_and_preserves(self, tmp_path) -> None:
        path = tmp_path / "config.toml"
        path.write_text('model = "gpt-5"\n')
        gate_install.install("codex", path, python="py")
        _, result = gate_install.install("codex", path, python="py")
        assert result == gate_install.ALREADY
        parsed = tomllib.loads(path.read_text())
        assert parsed["model"] == "gpt-5"
        assert "PreToolUse" in parsed["hooks"]

    def test_cursor_json(self, tmp_path) -> None:
        path = tmp_path / "hooks.json"
        gate_install.install("cursor", path, python="py")
        data = json.loads(path.read_text())
        assert data["hooks"]["beforeShellExecution"][0]["command"].endswith("--agent cursor")

    def test_gemini_json(self, tmp_path) -> None:
        path = tmp_path / "settings.json"
        gate_install.install("gemini", path, python="py")
        data = json.loads(path.read_text())
        cmd = data["hooks"]["BeforeTool"][0]["hooks"][0]["command"]
        assert cmd.endswith("--agent gemini")

    def test_unsupported_agent(self) -> None:
        with pytest.raises(gate_install.UnsupportedAgentError):
            gate_install.install("emacs", None)

    def test_installable_agents(self) -> None:
        assert set(gate_install.INSTALLABLE_AGENTS) == {"claude", "codex", "cursor", "gemini"}


class TestMainDispatch:
    def _run(self, agent: str, event: dict, monkeypatch: pytest.MonkeyPatch, capsys) -> str:
        monkeypatch.setattr(gate_main.sys, "stdin", io.StringIO(json.dumps(event)))
        gate_main.main(["--agent", agent])
        return capsys.readouterr().out

    def test_claude_deny(self, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        monkeypatch.setattr(
            gate,
            "scan",
            lambda _t: (
                "ok",
                {"risk_assessment": {"recommendation": "DO_NOT_INSTALL", "score": 9}},
            ),
        )
        out = self._run(
            "claude",
            {"tool_name": "Bash", "tool_input": {"command": "git clone https://e.com/x"}},
            monkeypatch,
            capsys,
        )
        assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_gemini_deny(self, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        monkeypatch.setattr(
            gate,
            "scan",
            lambda _t: (
                "ok",
                {"risk_assessment": {"recommendation": "DO_NOT_INSTALL", "score": 9}},
            ),
        )
        out = self._run(
            "gemini",
            {"tool_name": "run_shell_command", "tool_input": {"command": "git clone https://e/x"}},
            monkeypatch,
            capsys,
        )
        assert json.loads(out)["decision"] == "deny"

    def test_unrelated_no_output(self, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        out = self._run(
            "claude",
            {"tool_name": "Bash", "tool_input": {"command": "ls"}},
            monkeypatch,
            capsys,
        )
        assert out.strip() == ""


class _BytesStdin:
    """Fake stdin exposing a binary ``.buffer`` like a real piped stdin."""

    def __init__(self, data: bytes) -> None:
        self.buffer = io.BytesIO(data)

    def read(self) -> str:
        return self.buffer.getvalue().decode("utf-8-sig", errors="replace")


# The exact beforeShellExecution event captured live from Cursor agent 2026.06.29
# (command at top level; the real stdin is additionally prefixed with a UTF-8 BOM).
_REAL_CURSOR_EVENT = {
    "conversation_id": "8c1d2f6e",
    "model": "composer-2.5",
    "command": "git clone https://github.com/octocat/Hello-World",
    "cwd": "",
    "sandbox": False,
    "hook_event_name": "beforeShellExecution",
    "cursor_version": "2026.06.29-2ad2186",
    "workspace_roots": ["C:\\tmp"],
}


class TestCursorRealSchema:
    """Locks the adapter + stdin reader to Cursor's real, BOM-prefixed event."""

    def test_parse_real_cursor_event(self) -> None:
        assert (
            gate_agents.AGENTS["cursor"].parse(_REAL_CURSOR_EVENT)
            == "git clone https://github.com/octocat/Hello-World"
        )

    def test_bom_prefixed_event_still_denies(self, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        payload = b"\xef\xbb\xbf" + json.dumps(_REAL_CURSOR_EVENT).encode("utf-8")
        monkeypatch.setattr(
            gate,
            "scan",
            lambda _t: (
                "ok",
                {"risk_assessment": {"recommendation": "DO_NOT_INSTALL", "score": 9}},
            ),
        )
        monkeypatch.setattr(gate_main.sys, "stdin", _BytesStdin(payload))
        gate_main.main(["--agent", "cursor"])
        assert json.loads(capsys.readouterr().out)["permission"] == "deny"

    def test_double_bom_tolerated(self, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        payload = b"\xef\xbb\xbf\xef\xbb\xbf" + json.dumps(_REAL_CURSOR_EVENT).encode("utf-8")
        monkeypatch.setattr(
            gate,
            "scan",
            lambda _t: ("ok", {"risk_assessment": {"recommendation": "SAFE", "score": 0}}),
        )
        monkeypatch.setattr(gate_main.sys, "stdin", _BytesStdin(payload))
        gate_main.main(["--agent", "cursor"])
        assert json.loads(capsys.readouterr().out)["permission"] == "allow"
