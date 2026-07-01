# SkillSpector gate — Codex CLI

Scans a skill install with SkillSpector before Codex runs the command, and blocks anything rated
`DO_NOT_INSTALL`. This is the Codex adapter of the agent-agnostic gate in `skillspector.gate` — see
[../../docs/GUARDRAIL.md](../../docs/GUARDRAIL.md) for the shared design.

## Install

```bash
skillspector install-hook --agent codex
```

Idempotently adds a `PreToolUse` hook to `~/.codex/config.toml` that runs
`<python> -m skillspector.gate --agent codex` (using the interpreter that ran the installer). Start a
new Codex session for it to take effect.

## Config it writes

`~/.codex/config.toml`:

```toml
[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = '"<python>" -m skillspector.gate --agent codex'
timeout = 130
```

## What it gates

`git clone` URLs and `.zip`/`.tar` archive fetches are scanned directly; `apm install owner/repo`
and `npx owner/repo` are mapped to `https://github.com/owner/repo` and scanned; a bare `npx`/`apm`
package is surfaced for review (`ask`). The gate returns `allow` / `ask` / `deny` via
`hookSpecificOutput.permissionDecision` (Codex uses Claude Code's hook contract).

## Caveats

Codex hashes non-managed hooks and **skips them until you trust them** via `/hooks` in a session. For
a non-bypassable gate, deploy it as a **managed hook** (`requirements.toml` with `[features].hooks =
true`), optionally with `allow_managed_hooks_only = true`.

## Tested

Validated against **codex-cli 0.140.0** (logged in via ChatGPT):
- Config accepted — Codex parses the `[[hooks.PreToolUse]]` block without error.
- Adapter validated live end-to-end: a real `git clone` event → real `skillspector scan` → correct
  `permissionDecision: allow` on a safe repo; a bare-`npx` event → `permissionDecision: ask`.
- Live hook *firing* inside a session was not automated — it requires the one-time `/hooks` trust
  (or a managed-hook install) described above.
