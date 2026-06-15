# SPDX-FileCopyrightText: Copyright (c) 2026 Abhiram Dwivedi
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Claude Code PreToolUse gate (integrations/claude-code)."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_GATE_PATH = (
    Path(__file__).resolve().parents[2]
    / "integrations"
    / "claude-code"
    / "scripts"
    / "scan_gate.py"
)


def _load_gate():
    spec = importlib.util.spec_from_file_location("scan_gate", _GATE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


class TestExtractTarget:
    def test_git_clone_https(self) -> None:
        assert (
            gate.extract_target("Bash", {"command": "git clone https://github.com/x/y"})
            == "https://github.com/x/y"
        )

    def test_git_clone_with_git_suffix_and_dest(self) -> None:
        assert (
            gate.extract_target("Bash", {"command": "git clone https://github.com/x/y.git dest"})
            == "https://github.com/x/y.git"
        )

    def test_zip_archive_url(self) -> None:
        assert (
            gate.extract_target("Bash", {"command": "curl -O https://e.com/skill.zip"})
            == "https://e.com/skill.zip"
        )

    def test_unrelated_command_returns_none(self) -> None:
        assert gate.extract_target("Bash", {"command": "ls -la /tmp"}) is None

    def test_non_bash_tool_returns_none(self) -> None:
        assert gate.extract_target("WebFetch", {"url": "https://e.com/skill.zip"}) is None


class TestDecide:
    def test_safe_allows(self) -> None:
        decision, _ = gate.decide({"risk_assessment": {"recommendation": "SAFE", "score": 5}})
        assert decision == "allow"

    def test_do_not_install_denies(self) -> None:
        decision, _ = gate.decide(
            {"risk_assessment": {"recommendation": "DO_NOT_INSTALL", "score": 90}}
        )
        assert decision == "deny"

    def test_caution_asks_by_default(self) -> None:
        decision, _ = gate.decide({"risk_assessment": {"recommendation": "CAUTION", "score": 40}})
        assert decision == "ask"

    def test_caution_policy_override_deny(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SKILLSPECTOR_GATE_CAUTION", "deny")
        decision, _ = gate.decide({"risk_assessment": {"recommendation": "CAUTION", "score": 40}})
        assert decision == "deny"

    def test_unknown_recommendation_asks(self) -> None:
        decision, _ = gate.decide({"risk_assessment": {}})
        assert decision == "ask"


class TestScan:
    def test_no_tool_when_binary_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(gate.shutil, "which", lambda _name: None)
        status, report = gate.scan("https://x")
        assert status == "no_tool"
        assert report is None

    def test_error_on_exit_code_2(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(gate.shutil, "which", lambda _name: "/usr/bin/skillspector")
        monkeypatch.setattr(
            gate.subprocess, "run", lambda *a, **k: MagicMock(returncode=2, stdout="")
        )
        status, _ = gate.scan("https://x")
        assert status == "error"

    def test_ok_parses_report(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(gate.shutil, "which", lambda _name: "/usr/bin/skillspector")
        payload = json.dumps({"risk_assessment": {"recommendation": "SAFE", "score": 1}})
        monkeypatch.setattr(
            gate.subprocess, "run", lambda *a, **k: MagicMock(returncode=0, stdout=payload)
        )
        status, report = gate.scan("https://x")
        assert status == "ok"
        assert report["risk_assessment"]["recommendation"] == "SAFE"

    def test_target_passed_as_argv_not_shell(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(gate.shutil, "which", lambda _name: "/usr/bin/skillspector")
        captured: dict = {}

        def _fake_run(argv, **kwargs):
            captured["argv"] = argv
            captured["shell"] = kwargs.get("shell")
            return MagicMock(returncode=0, stdout="{}")

        monkeypatch.setattr(gate.subprocess, "run", _fake_run)
        gate.scan("https://evil.example/x; rm -rf /")
        assert captured["shell"] is False
        # The hostile target is a single argv element, never shell-interpolated.
        assert "https://evil.example/x; rm -rf /" in captured["argv"]


class TestMain:
    def _run(self, event: dict, monkeypatch: pytest.MonkeyPatch, capsys) -> str:
        monkeypatch.setattr(gate.sys, "stdin", io.StringIO(json.dumps(event)))
        gate.main()
        return capsys.readouterr().out

    def test_deny_on_high_risk(self, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
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
        out = self._run(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "git clone https://e.com/evil"},
            },
            monkeypatch,
            capsys,
        )
        decision = json.loads(out)["hookSpecificOutput"]["permissionDecision"]
        assert decision == "deny"

    def test_no_output_for_unrelated_command(self, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        out = self._run(
            {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}},
            monkeypatch,
            capsys,
        )
        assert out.strip() == ""

    def test_no_output_for_other_event(self, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        out = self._run({"hook_event_name": "SessionStart"}, monkeypatch, capsys)
        assert out.strip() == ""

    def test_no_tool_allows_with_warning(self, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        monkeypatch.setattr(gate, "scan", lambda _t: ("no_tool", None))
        out = self._run(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "git clone https://e.com/x"},
            },
            monkeypatch,
            capsys,
        )
        payload = json.loads(out)
        assert payload["hookSpecificOutput"]["permissionDecision"] == "allow"
        assert "systemMessage" in payload
