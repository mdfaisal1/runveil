# Runveil docs site

A self-contained, dependency-free static docs site (`index.html`) — getting
started, CLI reference (including `runveil config`), core concepts, the VS Code
extension, and deploy notes. It links into the repo
[README](../../README.md) and [docs/ci.md](../ci.md) rather than duplicating them.

## Serve / publish

```bash
# Local preview
python -m http.server -d docs/site 8000   # → http://localhost:8000

# GitHub Pages: point Pages at /docs (or publish docs/site/ as the site root)
```

No build step, no external assets.
