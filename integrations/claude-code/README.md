# SkillSpector — Claude Code guardrail plugin

A Claude Code **plugin** that runs a SkillSpector scan before the agent installs a skill and
blocks high-risk ones. (A *plugin*, not a bare skill — only plugins can ship hooks.) See
[../../docs/GUARDRAIL.md](../../docs/GUARDRAIL.md) for the architecture.

## What it does

- A **PreToolUse** hook ([`hooks/hooks.json`](hooks/hooks.json)) matches `Bash` tool calls. When the
  command fetches a skill from a scannable source — a `git clone <url>` or a `.zip` archive URL —
  the gate ([`scripts/scan_gate.py`](scripts/scan_gate.py)) runs
  `skillspector scan <target> --no-llm --format json` and returns a decision from
  `risk_assessment.recommendation`:

  | recommendation | decision |
  |----------------|----------|
  | `SAFE` | allow |
  | `CAUTION` | ask (prompt the user) |
  | `DO_NOT_INSTALL` | **deny** (block the install) |

- A manual skill ([`skills/skillspector-scan/`](skills/skillspector-scan/SKILL.md)) — invoke
  `/skillspector-guardrail:skillspector-scan` to scan any path/URL/zip on demand.

The gate stays out of the way for commands it doesn't recognise as a skill fetch (so normal Bash
usage is unaffected), and passes the scan target to `skillspector` as an **argv element with
`shell=False`** — a hostile command/URL can't inject into the gate's own subprocess.

## Install

Requires the `skillspector` CLI on `PATH` (`pip install skillspector` / this repo).

```bash
# From this repo (local/dev):
claude --plugin-dir integrations/claude-code

# Or via the marketplace defined at the repo root:
/plugin marketplace add AbhiramDwivedi/SkillSpector
/plugin install skillspector-guardrail@skillspector
```

## Configuration

- `SKILLSPECTOR_GATE_CAUTION` — how to treat a `CAUTION` verdict: `ask` (default), `deny`, or `allow`.
- Uses static analysis (`--no-llm`) for speed. To enable the LLM stage without an API key, set
  `SKILLSPECTOR_PROVIDER=claude_cli` in the environment (uses the local Claude login).

## Scope & limits (v1)

- **Covers agent-initiated installs only.** A hook fires only on the *agent's* tool calls — it can't
  stop a human running an install in their own terminal. That path is the [APM package](../apm/)'s job.
- Recognises `git clone` URLs and `.zip` archive URLs. Marketplace-ref installs
  (`/plugin install name@market`) and `WebFetch` aren't auto-scanned yet (the target isn't a directly
  scannable URL); they pass through untouched.
- **Windows:** the hook command uses `python3`. If your Windows Python is `python`, change the
  `command` in [`hooks/hooks.json`](hooks/hooks.json) accordingly.
