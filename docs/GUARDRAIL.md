# SkillSpector install-time guardrail — design

This fork extends SkillSpector from a manual scanner into an **install-time guardrail**: before an
AI agent "skill" is installed or used, run a SkillSpector scan and block it if the risk is too high
— unless explicitly approved. This document is the architecture reference for the work under
[`../integrations/`](../integrations/).

## The verdict the gate consumes

SkillSpector already produces everything a gate needs — no new scanner machinery required:

```bash
skillspector scan <path|url|zip> --format json
```

→ `risk_assessment.recommendation ∈ { SAFE, CAUTION, DO_NOT_INSTALL }` (plus `score`, `severity`).
The gate maps that verdict to an action:

| `recommendation` | action |
|------------------|--------|
| `SAFE` | allow |
| `CAUTION` | prompt / warn |
| `DO_NOT_INSTALL` | block |

Strictness (e.g. treat `CAUTION` as block in CI) is a **gate policy** decision, not a scanner flag.
Exit codes: `0` (score ≤ 50), `1` (> 50), `2` (error) — note the exit code alone can't distinguish
`SAFE` from `CAUTION`, so the gate reads the JSON `recommendation`. (See the README "Integrating
SkillSpector" section.)

## Two enforcement surfaces

A skill gets installed two ways, and a single mechanism can't cover both:

| Surface | Covers | Mechanism | Lives in |
|---------|--------|-----------|----------|
| **Agent-initiated** | The agent installs/fetches a skill mid-session | Pre-tool hook for Claude Code, Codex, Cursor, Gemini | `skillspector.gate` + `integrations/claude-code/` |
| **Human / CI-initiated** | A person or pipeline runs the package manager | **APM**: `apm.yml` + policy / pre-install hook calling SkillSpector | `integrations/apm/` |

**Enforcement boundary (important):** a pre-tool hook fires only on the *agent's* tool calls
within a session — it cannot stop a human running `claude plugin install` / `git clone` in their own
terminal. APM covers that human/CI path. The guardrail is **defense-in-depth, not a sandbox**.

## Supported agents & install triggers

The gate logic lives once in the agent-agnostic `skillspector.gate` package; thin per-agent
adapters translate each CLI's hook event/response schema (they all share the same shape — a command
handler, the tool call as JSON on stdin, and a `deny` decision — so only the field names differ):

| Agent | Hook event | Config | Install with |
|-------|-----------|--------|--------------|
| Claude Code | `PreToolUse` | `~/.claude/settings.json` | `skillspector install-hook --agent claude` (or the marketplace plugin) |
| Codex CLI | `PreToolUse` | `~/.codex/config.toml` | `skillspector install-hook --agent codex` |
| Cursor | `beforeShellExecution` | `~/.cursor/hooks.json` | `skillspector install-hook --agent cursor` |
| Gemini CLI | `BeforeTool` | `~/.gemini/settings.json` | `skillspector install-hook --agent gemini` |

`skillspector install-hook --agent all` configures every installed agent at once. Each installer is
idempotent and writes a hook that runs `<python> -m skillspector.gate --agent <name>` using the
interpreter that ran the installer, so the hook always resolves the `skillspector` package.

The gate recognises these install commands in a tool call and scans the target before it runs:

- `git clone <url>` — scanned directly.
- `.zip` / `.tar(.gz|.bz2)` archive fetches (`curl`/`wget`) — scanned directly.
- `apm install owner/repo` and `npx owner/repo` — mapped to `https://github.com/owner/repo` and scanned.
- a bare `npx`/`apm` package (no repo slug) — not directly scannable, so surfaced as **ask** for review.

> Gemini's hook has no interactive "ask", so a `CAUTION` result there fails safe to **deny** with a
> reason (opt out with `SKILLSPECTOR_GATE_CAUTION=allow`). Cursor's `allow`/`ask` are unreliable in
> some builds, but its `deny` — the direction that matters for a security gate — is honoured.

The marketplace plugin under `integrations/claude-code/` ships a **self-contained** `scan_gate.py`
(depends only on the `skillspector` CLI, not the importable package) so it works no matter how the
scanner was installed; a consistency test keeps its detection in lock-step with the package.

## How the gate scans (cheap + local)

- The gate runs `skillspector scan <fetched-target> --format json` and reads `recommendation`.
- The target is scannable directly: SkillSpector accepts a Git URL / zip / directory, so the hook
  can scan *before* the skill lands on disk.
- For the LLM stage with **no API key**, the gate can use the local-CLI provider
  (`SKILLSPECTOR_PROVIDER=claude_cli`, added in this fork) — it reuses the user's existing `claude`
  login. For a fast inline gate, static-only (`--no-llm`) is the default; escalate to the LLM only on
  borderline (`CAUTION`) results.

## Layout

```
integrations/
  claude-code/   # Claude Code guardrail plugin (skill + PreToolUse hook + command)
  apm/           # Microsoft APM package + policy gate
```

## Build order

1. `integrations/` scaffold + this design doc.
2. Cross-platform fix so the base is green on all OSes (`build_context` path handling).
3. Claude Code plugin (agent-initiated gate).
4. APM packaging + policy gate (human/CI gate).
