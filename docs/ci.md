# Running Runveil in CI

Runveil exits non-zero (code `3`) when a **reachable** finding meets or exceeds your
`--fail-on` threshold. Dormant (dev-only) findings never fail the build — that's the
point. Drop one of the snippets below into your pipeline.

Each example installs Runveil with `go install` (requires a Go toolchain) and then
runs the scan.

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
          go install github.com/mdfaisal1/runveil/cmd/runveil@latest
          echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"
      - name: Scan
        run: runveil scan package-lock.json --fail-on high
```

## GitLab CI

```yaml
runveil-scan:
  image: golang:1.25
  script:
    - go install github.com/mdfaisal1/runveil/cmd/runveil@latest
    - export PATH="$PATH:$(go env GOPATH)/bin"
    - runveil scan package-lock.json --fail-on high
```

## Jenkins (declarative pipeline)

```groovy
pipeline {
  agent { docker { image 'golang:1.25' } }
  stages {
    stage('Runveil scan') {
      steps {
        sh 'go install github.com/mdfaisal1/runveil/cmd/runveil@latest'
        sh 'export PATH="$PATH:$(go env GOPATH)/bin"; runveil scan package-lock.json --fail-on high'
      }
    }
  }
}
```

## Generic / any CI

```bash
go install github.com/mdfaisal1/runveil/cmd/runveil@latest
export PATH="$PATH:$(go env GOPATH)/bin"
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
