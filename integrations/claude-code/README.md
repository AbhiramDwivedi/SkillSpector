# SkillSpector — Claude Code guardrail plugin

A Claude Code **plugin** that runs a SkillSpector scan before a skill is installed and blocks
high-risk skills. (A *plugin*, not a bare skill — only plugins can ship hooks.)

Planned structure:

```
.claude-plugin/
  plugin.json        # plugin manifest
  marketplace.json   # for installation via a marketplace
skills/
  skillspector-scan/
    SKILL.md         # manual /scan-skill capability
hooks/
  hooks.json         # PreToolUse gate (+ SessionStart inventory scan)
  scan_gate.py       # gate script: scan the fetched target -> allow/ask/deny
```

How it works: a **PreToolUse** hook matches the tool calls that fetch/install a skill (Bash
`git clone` / package-manager commands, or `WebFetch` of a skill URL), runs
`skillspector scan <target> --format json`, and returns `allow` / `ask` / `deny` from
`risk_assessment.recommendation`. See [../../docs/GUARDRAIL.md](../../docs/GUARDRAIL.md).

> Covers **agent-initiated** installs only — a hook cannot intercept a human installing in their own
> terminal (that's the APM package's job).

**Status:** scaffolding.
