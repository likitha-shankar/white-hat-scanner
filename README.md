# White Hat

[![CI](https://github.com/likitha-shankar/white-hat-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/likitha-shankar/white-hat-scanner/actions/workflows/ci.yml)
[![Live Demo](https://img.shields.io/badge/live%20demo-online-2ea44f)](https://white-hat-demo.onrender.com/)

**▶ Live demo: https://white-hat-demo.onrender.com/** — scan a **public GitHub repo** (paste `github.com/owner/repo`) or try the bundled samples, right in your browser (free tier; first load may cold-start for a few seconds).

Dual-mode security analysis. It **proves** findings instead of guessing, and stages exact fixes for review — it never edits your code without an explicit click.

- **Mode 2 — white-box:** static analysis of a JS/TS codebase. Injection, authorization, JWT, race conditions, crypto, secrets. Each confirmed finding carries a runnable proof or a reproduction path, plus a before/after remediation diff.
- **Mode 1 — black-box:** passive live-URL surface scan. Security headers, cookies, CORS, exposed paths, JS-bundle secrets, source maps. Reads what a normal browser session exposes plus a targeted, read-only probe. No payloads, no brute force, no exploitation.

## Three surfaces, one engine

| Surface | Modes | Use |
|---|---|---|
| **CLI / engine** (`src/`) | 2 + 1 | Scriptable, CI gating, JSON output |
| **VS Code extension** (`vscode-extension/`) | 2 + 1 | Sidebar report, native diff, click-to-apply fixes |
| **Browser plugin** (`browser-plugin/`) | 1 | Persistent side panel while you browse |

The CLI, the VS Code worker, and the browser plugin all drive the same detection logic.

## Quick start

### CLI

```bash
npm install
node src/index.js <folder>                 # Mode 2: scan a codebase
node src/index.js --url https://example.com # Mode 1: scan a live URL
node src/index.js <folder> --json           # machine-readable
node src/index.js <folder> --report out.md  # write the report to a file
```

Exit code is `1` when a Critical/High is confirmed — drop it into CI.

### VS Code extension

Install the packaged build: `code --install-extension vscode-extension/white-hat-vscode-0.1.0.vsix`
(or open `vscode-extension/` in VS Code and press **F5** for a dev host).

Click the **White Hat shield** in the activity bar → enter a folder path or `https://` URL → **Scan**. Use **View Diff** to compare before/after, **Apply** to write a safe fix. Analysis runs in a worker thread; the UI never blocks.

### Browser plugin (Chrome/Edge, MV3)

`chrome://extensions` → Developer mode → **Load unpacked** → select `browser-plugin/`. Click the toolbar icon to open the side panel, then browse. Findings populate from real response headers, the live DOM, and a targeted probe, and persist across navigation.

## What it detects

**Mode 2 (white-box), proven with taint/AST analysis:**

| Class | Confirmed by |
|---|---|
| SQL Injection | intraprocedural taint → query sink |
| Command Injection | taint → `exec`/`execSync` |
| Path Traversal | taint → fs / `sendFile` sink |
| Hardcoded Secret | provider-format regex proof |
| Weak Crypto (MD5/SHA1/ECB, `Math.random`) | runnable primitive check |
| Non-constant-time Comparison | secret-typed operands (heuristic) |
| Broken Object-Level Auth (BOLA/IDOR) | handler-scope ownership check absence |
| JWT Implementation Errors | missing `algorithms`/expiry, `none`, decode-for-auth, literal secret |
| Race Conditions (TOCTOU) | read→write in async handler, no transaction/lock |

Architectural classes (BOLA, JWT, TOCTOU) are reported **Unconfirmed** with a reproduction path — they need human verification by design.

**Mode 1 (black-box):** missing/weak security headers, insecure cookie flags, permissive CORS, version disclosure, mixed content, credentials over HTTP, secrets/tokens in URLs, exposed sensitive paths (`/.env`, `/.git`, actuator, metrics…), directory listing, exposed source maps, verbose error/stack-trace leaks.

## How it works

- **Proof over noise.** Runnable checks execute an isolated reconstruction of the flaw (never your code): the secret's format is validated, the weak hash is actually computed. Everything else ships a step-by-step reproduction. Unprovable matches are separated into an Unconfirmed section, not dropped.
- **Remediation.** Every confirmed finding includes a before/after diff and a note asserting the output contract, complexity, and side effects are preserved. Fixes that are real source transforms (secrets, insecure randomness, timing comparison) are click-to-apply; illustrative ones are advisory (Apply disabled).
- **Memory.** `white_hat_memory.md` records confirmed vulnerability *classes*; later runs flag known patterns first.

## Architecture

- **Parser boundary** (`src/parse.js`) — Babel today; swap for tree-sitter to go polyglot without touching detectors.
- **Chunker** (`src/walk.js`) — groups files into logical units (routing/auth/db/crypto/…) for context and cross-unit state.
- **Detector registry** (`src/detectors/index.js`) — each detector is one file exporting `scan(file, ast, helpers)`. Adding a class is one file + one line.
- **Taint** (`src/parse.js`) — lightweight intraprocedural: params and `req.*` flow to sinks within a function.
- **Proof harness** (`src/prove.js`) — runs runnable checks in an isolated child process.
- **Shared Mode 1 rules** (`browser-plugin/rules.js`) — dependency-free, runs in the service worker, the content script, and the node self-test.

## Tests

```bash
npm test   # node --test
```

13 tests: Mode 2 detectors on vulnerable + clean fixtures, Mode 1 against local vulnerable/secure servers, and the browser plugin's pure rules.

## Limitations

- Taint is intraprocedural — input laundered through a helper is a false negative (needs a call graph).
- Architectural detectors (BOLA/JWT/TOCTOU) are handler-scope heuristics → always Unconfirmed.
- Mode 2 targets JS/TS. Mode 1 stays strictly passive (no rate-limit timing / GraphQL introspection probing).
- The browser plugin scans same-origin scripts and a short sensitive-path list to stay non-aggressive.

## Layout

```
src/                 engine: walker, parser, detectors, proof, report, memory, mode1
vscode-extension/    MV-based VS Code extension (bundles the engine into ./engine for .vsix)
browser-plugin/      Chrome MV3 plugin (Mode 1 side panel)
tests/               node --test suites + fixtures
```
