---
name: skillspector-scan
description: Scan an AI agent skill (a directory, git URL, or zip) with SkillSpector and report its risk. Use before installing or trusting a skill from an untrusted source.
---

# Scan a skill with SkillSpector

When the user wants to vet a skill before installing or trusting it, run a
SkillSpector scan and report the verdict.

```bash
skillspector scan <PATH_OR_GIT_URL_OR_ZIP> --no-llm --format json
```

Summarize `risk_assessment` (`score`, `severity`, `recommendation`) and the top
`issues`, then advise per the recommendation: **SAFE** (safe to install),
**CAUTION** (review findings first), **DO_NOT_INSTALL** (do not install).

To gate this automatically in CI, see [`../../ci-gate.md`](../../ci-gate.md):
`skillspector scan` exits `1` when `risk_score > 50`, which fails the build.
