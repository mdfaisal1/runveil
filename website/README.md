# Runveil — Marketing Website

The public landing page for [runveil.com](https://runveil.com). Static site, **no build step** —
plain HTML, CSS, and vanilla JS so Cloudflare Pages can serve it directly.

```
website/
├── index.html     # all sections (hero, before/after, terminal, how-it-works, features, CTA)
├── styles.css     # dark/cyan theme + animations
├── app.js         # scroll reveals, counters, typed terminal, canvas graph, live GitHub stars
├── _headers       # security + cache headers for Cloudflare Pages
└── README.md       # this file
```

## Preview locally

No tooling required — just open `index.html`. To serve it with correct paths:

```bash
# from the website/ folder
python -m http.server 8000
# then open http://localhost:8000
```

## Deploy to Cloudflare Pages (connect this GitHub repo)

> Your current runveil.com serves a single `index.html` uploaded manually. These steps
> replace that with this Git-connected project so every push auto-deploys.

1. **Rename the GitHub repo to `runveil`** (Settings → General → Rename) so the
   `github.com/mdfaisal1/runveil` links and the live star count work. Update your
   local remote afterwards:
   ```bash
   git remote set-url origin git@github.com:mdfaisal1/runveil.git
   ```
2. **Push this `website/` folder** to GitHub (commit + push to `main`).
3. In the **Cloudflare dashboard** → **Workers & Pages** → **Create** → **Pages** →
   **Connect to Git**. Authorize GitHub and pick the `runveil` repo.
4. Set the build configuration:
   - **Framework preset:** `None`
   - **Build command:** *(leave empty)*
   - **Build output directory:** `website`
   - **Root directory:** *(leave as repo root)*
5. **Save and Deploy.** Cloudflare builds a `*.pages.dev` preview URL.
6. **Custom domain:** in the new Pages project → **Custom domains** → **Set up a
   custom domain** → enter `runveil.com`. Cloudflare wires the DNS automatically
   since the domain is already in your account.

> ⚠️ If you have an existing Pages project (the manually-uploaded `index.html` one),
> remove the `runveil.com` custom domain from it first, or create this new project
> and move the domain over. Two projects can't claim the same domain.

After this, every `git push` to `main` redeploys the site automatically.

## Editing content

- **GitHub links / repo name** — search for `mdfaisal1/runveil` in `index.html` and `app.js`.
- **Install command** — `index.html` (`#install-text`) and `app.js` (`copyBtn` handler). Keep them in sync.
- **Terminal output** — the `TERM_LINES` array in `app.js`.
- **Before/after numbers** — the `data-count` attributes in `index.html` (`187` → `6`).
