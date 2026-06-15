---
name: skillspector-scan
description: Scan an AI agent skill (a directory, git URL, or zip) with SkillSpector and report its risk. Use before installing or trusting a skill from an untrusted source.
---

# Scan a skill with SkillSpector

When the user wants to vet a skill before installing or trusting it, run a
SkillSpector scan and report the verdict.

Run a fast static scan:

```bash
skillspector scan <PATH_OR_GIT_URL_OR_ZIP> --no-llm --format json
```

Then summarize `risk_assessment` (`score`, `severity`, `recommendation`) and the
top entries in `issues`. Advise per the recommendation:

- **SAFE** — safe to install.
- **CAUTION** — review the findings first; install only if they're acceptable.
- **DO_NOT_INSTALL** — do not install.

For deeper analysis, drop `--no-llm` to enable the LLM stage. With
`SKILLSPECTOR_PROVIDER=claude_cli` it uses the local Claude login (no API key).

> This is the *manual* companion to the automatic PreToolUse gate in this plugin,
> which scans skills the agent tries to install and blocks high-risk ones.
