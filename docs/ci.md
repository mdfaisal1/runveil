# Running Runveil in CI

Runveil exits non-zero (code `3`) when a **reachable** finding meets or exceeds your
`--fail-on` threshold. Dormant (dev-only) findings never fail the build — that's the
point. Drop one of the snippets below into your pipeline.

> Until prebuilt binaries / `go install` are published, CI builds Runveil from source.
> Each example clones and builds it once, then runs the scan.

## GitHub Actions

A ready-to-use workflow lives at
[.github/workflows/runveil-scan.yml](../.github/workflows/runveil-scan.yml). Minimal form:

```yaml
name: Runveil
on: [push, pull_request]
jobs:
  reachable-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.25' }
      - name: Install Runveil
        run: |
          git clone --depth 1 https://github.com/mdfaisal1/runveil /tmp/runveil
          (cd /tmp/runveil && go build -o "$RUNNER_TEMP/runveil" ./cli)
          echo "$RUNNER_TEMP" >> "$GITHUB_PATH"
      - name: Scan
        run: runveil scan package-lock.json --fail-on high
```

## GitLab CI

```yaml
runveil-scan:
  image: golang:1.25
  script:
    - git clone --depth 1 https://github.com/mdfaisal1/runveil /tmp/runveil
    - (cd /tmp/runveil && go build -o /usr/local/bin/runveil ./cli)
    - runveil scan package-lock.json --fail-on high
```

## Jenkins (declarative pipeline)

```groovy
pipeline {
  agent { docker { image 'golang:1.25' } }
  stages {
    stage('Runveil scan') {
      steps {
        sh 'git clone --depth 1 https://github.com/mdfaisal1/runveil /tmp/runveil'
        sh 'cd /tmp/runveil && go build -o /usr/local/bin/runveil ./cli'
        sh 'runveil scan package-lock.json --fail-on high'
      }
    }
  }
}
```

## Generic / any CI

```bash
git clone --depth 1 https://github.com/mdfaisal1/runveil /tmp/runveil
(cd /tmp/runveil && go build -o /usr/local/bin/runveil ./cli)
runveil scan package-lock.json --fail-on high   # exit 3 on reachable >= high
```

## Tuning the gate

| Flag value | Build fails when a reachable finding is… |
| --- | --- |
| `none` (default) | never — report only |
| `low` | low or higher |
| `medium` | medium or higher |
| `high` | high or critical |
| `critical` | critical only |

Use `--format md --out report.md` to also emit a Markdown report you can publish as a
CI artifact or job summary.
