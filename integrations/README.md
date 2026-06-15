# integrations/

Install-time guardrail built on SkillSpector. See [../docs/GUARDRAIL.md](../docs/GUARDRAIL.md) for
the architecture.

- [`claude-code/`](claude-code/) — Claude Code **plugin**: scans a skill before the agent installs
  it and returns allow / ask / deny. Covers **agent-initiated** installs.
- [`apm/`](apm/) — Microsoft **APM** package + policy gate. Covers **human / CI-initiated** installs.

Both call `skillspector scan … --format json` and act on `risk_assessment.recommendation`
(`SAFE` → allow, `CAUTION` → prompt, `DO_NOT_INSTALL` → block).
