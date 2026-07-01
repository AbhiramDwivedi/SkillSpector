# SkillSpector gate — Gemini CLI

Scans a skill install with SkillSpector before Gemini runs the command, and blocks anything rated
`DO_NOT_INSTALL`. This is the Gemini adapter of the agent-agnostic gate in `skillspector.gate` — see
[../../docs/GUARDRAIL.md](../../docs/GUARDRAIL.md) for the shared design.

## Install

```bash
skillspector install-hook --agent gemini
```

Idempotently adds a `BeforeTool` hook to `~/.gemini/settings.json` that runs
`<python> -m skillspector.gate --agent gemini`. Start a new Gemini session for it to take effect.

## Config it writes

`~/.gemini/settings.json`:

```json
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command|Shell|Bash",
        "hooks": [
          {
            "name": "skillspector-gate",
            "type": "command",
            "command": "\"<python>\" -m skillspector.gate --agent gemini",
            "timeout": 130
          }
        ]
      }
    ]
  }
}
```

## What it gates

Same detection as the other adapters (git clone, `.zip`/`.tar`, `apm`/`npx` repo slugs → scanned;
bare packages → review). The gate blocks by returning `{"decision": "deny", "reason": ...}`.

## Caveats

Gemini's hook has **no interactive "ask"**, so a `CAUTION` result fails safe to **deny** with a
self-documenting reason (opt out with `SKILLSPECTOR_GATE_CAUTION=allow`). For defense in depth, pair
this with a Policy Engine `deny` rule (`~/.gemini/policies/*.toml`) for known-bad install commands.

## Tested

Validated against **gemini-cli 0.46.0**:
- Adapter validated live: a `run_shell_command` event on a bare-`npx` install → correct
  `{"decision": "deny", ...}` with the ask→deny downgrade note; the scanner independently rates the
  bundled malicious fixture `DO_NOT_INSTALL` (score 93).
- Config schema matches Gemini's documented `hooks.BeforeTool` format.
- **Full E2E (hook firing in a live session) was blocked by authentication**, not by the gate: as of
  mid-2026 Google restricted the individual-tier Gemini CLI login
  (`IneligibleTierError`, redirecting to the Antigravity suite). Run the E2E on an eligible tier
  (Vertex AI / Gemini API key) to exercise the live hook.
