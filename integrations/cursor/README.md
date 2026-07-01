# SkillSpector gate — Cursor CLI

Scans a skill install with SkillSpector before Cursor runs the command, and blocks anything rated
`DO_NOT_INSTALL`. This is the Cursor adapter of the agent-agnostic gate in `skillspector.gate` — see
[../../docs/GUARDRAIL.md](../../docs/GUARDRAIL.md) for the shared design.

## Install

```bash
skillspector install-hook --agent cursor
```

Idempotently adds a `beforeShellExecution` hook to `~/.cursor/hooks.json` that runs
`<python> -m skillspector.gate --agent cursor`. Start a new Cursor session for it to take effect.

## Config it writes

`~/.cursor/hooks.json`:

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      { "command": "\"<python>\" -m skillspector.gate --agent cursor" }
    ]
  }
}
```

## What it gates

Same detection as the other adapters (git clone, `.zip`/`.tar`, `apm`/`npx` repo slugs → scanned;
bare packages → review). The gate blocks by returning `{"permission": "deny", ...}`.

## Caveats

- Only the **`deny`** direction is relied on — the direction that matters for a security gate. In
  some builds Cursor's `allow`/`ask` are unreliable (an allow-list can override), but `deny` is
  honoured.
- Cursor hooks default to **fail-open**, so the gate emits `deny` on internal error rather than
  silently allowing.
- The headless `cursor-agent` fires `beforeShellExecution` (what this gate uses); it does **not**
  fire `beforeMCPExecution` (IDE-only), so MCP-call gating in headless mode is a known gap.

## Tested

Validated live against **Cursor `agent` 2026.06.29** (authenticated):
- The `beforeShellExecution` hook fires in headless (`-p`) mode and Cursor honours the gate's
  response **both ways**: a `deny` blocked a `git clone` ("A Cursor hook blocked it"); an `allow` let
  a safe repo through ("The repository was cloned successfully").
- The shipped `python -m skillspector.gate --agent cursor` parses Cursor's real event end-to-end and
  returns the right decision from a live scan (e.g. `{"permission": "allow", ...}` on a SAFE repo).
- Cursor prefixes the hook's stdin with a **UTF-8 BOM**; the gate reads it via `utf-8-sig`
  (regression-tested with the captured event). Note the CLI binary is `agent` (a `.ps1` on Windows),
  not `cursor-agent`.
