# Runveil for VS Code

Surfaces a Runveil project's vulnerability findings in a dedicated sidebar view —
reachable findings first, severity-ranked, the same prioritization as the CLI and
dashboard.

## Setup

Read endpoints are **org-scoped and require a credential**, so the extension needs
a read-scoped API key:

```bash
runveil keys create --scope read --org <your-org>
```

Then run **Runveil: Configure** (command palette) to set your project slug and
paste the key, or set them in Settings:

| Setting | Description |
| --- | --- |
| `runveil.apiBase` | Runveil API base URL (default `http://localhost:8080`) |
| `runveil.token` | Read-scoped API key (`rv_…`) |
| `runveil.project` | Project slug to display |

Open the **Runveil** view in the activity bar and hit refresh.

## Develop

```bash
npm install
npm run typecheck   # tsc --noEmit
npm run build       # esbuild bundle -> dist/extension.js
```

> Status: v0.1 — read-only findings view. Inline editor diagnostics (mapping
> findings to `package-lock.json` ranges) are a planned follow-up.
