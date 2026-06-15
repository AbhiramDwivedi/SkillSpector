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
| **Agent-initiated** | The agent installs/fetches a skill mid-session | Claude Code **plugin**: PreToolUse hook (+ skill + command) | `integrations/claude-code/` |
| **Human / CI-initiated** | A person or pipeline runs the package manager | **APM**: `apm.yml` distributes the skill; a **CI gate** (`skillspector scan`) enforces | `integrations/apm/` |

**Enforcement boundary (important):** a Claude Code hook fires only on the *agent's* tool calls
within a session — it cannot stop a human running `claude plugin install` / `git clone` in their own
terminal. APM covers that human/CI path. The guardrail is **defense-in-depth, not a sandbox**.

**Verified APM constraint:** APM hooks are advisory and cannot block an install, and `apm-policy.yml`
enforces only static allow/deny lists — neither can call an external scanner. So the APM-side gate is
a **CI check** built on SkillSpector's exit code (`1` on `DO_NOT_INSTALL`), not an inline pre-install
hook. See [`../integrations/apm/ci-gate.md`](../integrations/apm/ci-gate.md).

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
