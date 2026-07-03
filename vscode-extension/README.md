# White Hat Security (VS Code)

White-box (Mode 2) and black-box (Mode 1) security analysis in a sidebar.

- **Folder path** → static analysis of your JS/TS code: injection, path traversal, BOLA, JWT flaws, race conditions, weak crypto, hardcoded secrets. Findings are **proven** (runnable checks or reproduction paths), ranked by severity, with remediation shown as a before/after diff.
- **`https://` URL** → passive live-surface scan: security headers, cookies, CORS, exposed paths, JS-bundle secrets, source maps.

## Use

1. Click the **White Hat shield** in the activity bar.
2. Enter a folder path or a URL (blank = workspace root) and hit **Scan**.
3. **View Diff** shows before/after side by side. **Apply** writes a fix to disk — only for safe, source-preserving remediations, and only on your click.

The scan runs in a worker thread; the UI never blocks. Nothing is written without explicit approval.

## Settings

- `whiteHat.enginePath` — override the analysis engine entry point. Defaults to the engine bundled with the extension.
