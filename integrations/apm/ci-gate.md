# Gating APM skill installs with SkillSpector in CI

**Why CI:** Microsoft APM does not run an external scanner as a *blocking* pre-install hook. APM hooks
are advisory (they deploy to the harness and run *after* install), and `apm-policy.yml` enforces only
static allow/deny lists — it can't call `skillspector scan`. So enforcement for human/CI-initiated
installs lives in **CI**, using SkillSpector's stable contract.

SkillSpector exits **`1` when `risk_score > 50`** (i.e. `DO_NOT_INSTALL`) and `0` otherwise — so a
plain `skillspector scan` in a CI step fails the build on a high-risk skill, no parsing required.

## Minimal gate (exit code)

```yaml
# .github/workflows/skill-gate.yml — in the repo that consumes APM skills
name: skill-gate
on: [pull_request]
jobs:
  skillspector:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pipx install skillspector
      # Scan the vendored/authored skills; non-zero exit (risk > 50) fails the job.
      - run: skillspector scan .apm/skills --no-llm
```

For stricter gating (block on `CAUTION` too), read the JSON `recommendation` instead of the exit code:

```bash
rec=$(skillspector scan .apm/skills --no-llm --format json | jq -r '.risk_assessment.recommendation')
[ "$rec" = "SAFE" ] || { echo "Blocked: $rec"; exit 1; }
```

## Surfacing findings (SARIF)

SkillSpector emits SARIF 2.1.0, so findings can show up in GitHub code scanning:

```yaml
      - run: skillspector scan .apm/skills --no-llm --format sarif -o skillspector.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skillspector.sarif
```

## Native APM audit (experimental)

If your APM version supports external scanners, APM can ingest SkillSpector's SARIF in `apm audit`:

```bash
skillspector scan .apm/skills --no-llm --format sarif -o skillspector.sarif
apm audit --ci --external skillspector --external-sarif skillspector.sarif
```

> Verify against your APM version — external-scanner ingestion is marked experimental in the APM docs
> (`apm experimental enable external-scanners`). The exit-code gate above needs no APM features and is
> the durable baseline.
