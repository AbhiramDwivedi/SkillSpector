# SkillSpector — Microsoft APM package

Distributes the guardrail via [Microsoft APM](https://microsoft.github.io/apm/) across harnesses,
and — where APM supports it — wires SkillSpector behind a policy / pre-install hook so
**human- and CI-initiated** installs are gated too. That's the path a Claude Code hook can't reach.

Planned structure:

```
apm.yml            # package manifest
apm-policy.yml     # policy gate invoking SkillSpector (pending blocking-semantics verification)
.apm/
  hooks/           # pre-install hook running `skillspector scan`
```

See [../../docs/GUARDRAIL.md](../../docs/GUARDRAIL.md).

> **Open question to verify during build:** whether an APM policy / pre-install hook can actually
> *block* an install on a non-zero result, or is advisory-only. If it can't block, this degrades to
> distribution + advisory scanning, and enforcement leans on the built-in APM pre-deploy scan.

**Status:** scaffolding.
