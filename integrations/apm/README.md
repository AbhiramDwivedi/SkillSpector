# SkillSpector — Microsoft APM package

Distributes the guardrail skill via [Microsoft APM](https://microsoft.github.io/apm/) across
APM-supported harnesses, and gates **human- and CI-initiated** installs — the path a Claude Code
hook can't reach.

## What we verified (and what it means)

We checked the APM docs before building. The result reshaped the design:

- **APM hooks cannot block an install.** They're advisory — deployed to the harness and run *after*
  install; there is no `PreInstall` hook.
- **`apm-policy.yml` *can* block** (`enforcement: block` aborts before files are written), but it
  enforces only **static** dependency allow/deny lists — it cannot invoke an external scanner like
  `skillspector scan`.
- **So enforcement lives in CI**, using SkillSpector's stable contract: `skillspector scan` exits `1`
  on `DO_NOT_INSTALL` (`risk_score > 50`), which fails the build. Optionally, SkillSpector's SARIF can
  be ingested via `apm audit --external` (experimental).

## Contents

```
apm.yml                                  # package manifest (distribution)
.apm/skills/skillspector-scan/SKILL.md   # the scan skill, deployed across harnesses
ci-gate.md                               # the enforcement recipe (CI)
```

- **Distribution:** `apm install skillspector-guardrail` (from this package) deploys the scan skill to
  whatever harness APM targets.
- **Enforcement:** see [`ci-gate.md`](ci-gate.md) — add `skillspector scan` as a required CI check
  around `apm install`.

See [../../docs/GUARDRAIL.md](../../docs/GUARDRAIL.md).
