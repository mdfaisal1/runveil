# Launch-testing & publishing the Runveil extension

The extension is **type-checked, bundled, and packaged** in CI-style here, but two
steps require a real editor / a marketplace account and must be done by a human.

## 1. Launch-test (Extension Development Host)

```bash
cd editors/vscode
npm install
npm run build
# Open this folder in VS Code, press F5 (Run > Start Debugging).
# A second "[Extension Development Host]" window opens with the extension loaded.
```

In that window:
1. Run **Runveil: Configure** → enter a project slug and a read-scoped key
   (`runveil keys create --scope read --org <org>`).
2. Open the **Runveil** view in the activity bar → confirm findings load,
   reachable-first and severity-ranked.
3. Verify the error paths: a bad token shows the "Unauthorized" message; an
   unknown project shows "Project not found".

## 2. Install the packaged VSIX locally (optional smoke test)

```bash
npx vsce package          # produces runveil-<version>.vsix
code --install-extension runveil-0.1.0.vsix
```

## 3. Publish to the Marketplace

Requires a [publisher](https://marketplace.visualstudio.com/manage) and an Azure
DevOps Personal Access Token with **Marketplace > Manage** scope.

```bash
# one-time
npx vsce login <publisher>     # paste the PAT

# each release (bump "version" in package.json first)
npx vsce publish
```

> Before the first real publish: add a 128×128 PNG `icon` to `package.json`
> (the activity-bar `media/runveil.svg` is separate), and replace the placeholder
> `publisher: "runveil"` with your actual publisher id.
