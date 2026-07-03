# White Hat — Setup, Testing & Live Demo

Everything you need to install, run, and see results. Copy-paste the commands.

---

## 1. Prerequisites

- **Node.js 18+** (tested on Node 25). Check: `node -v`
- No database, no API keys, no network needed for Mode 2.

---

## 2. Install

```bash
cd "/Users/likitha/Desktop/hmm/projects/white hat"
npm install
```

That pulls two pure-JS deps (`@babel/parser`, `@babel/traverse`). Done in ~1s.

---

## 3. See it live in your browser ⭐ (easiest way to view results)

```bash
npm run demo
```

Then open **http://localhost:7777** (or the port printed in the terminal).

- The box accepts a **folder path** (Mode 2 — code analysis) or an **https:// URL** (Mode 1 — live surface scan).
- It loads pre-filled with the built-in vulnerable fixtures so you see findings immediately.
- Findings are ranked by severity, color-coded, each with impact, proof, and a before/after remediation diff.

Try these in the box:
| Enter this | Shows |
|---|---|
| `tests/fixtures/vuln` | 7 confirmed + 7 unconfirmed across all 9 detector classes |
| `tests/fixtures/gqltrpc` | 7 SQL injections via GraphQL / tRPC / TypeGraphQL sources |
| `tests/fixtures/interproc` | cross-file + cross-function taint |
| `src` | the engine scanning itself — **0 findings** (clean) |
| `https://example.com` | live header/cookie/CORS/path surface scan |

Stop the server with `Ctrl+C`.

---

## 4. Command line

### Mode 2 — scan a codebase
```bash
node src/index.js <folder>                    # ranked report to the terminal
node src/index.js <folder> --report out.md    # write the report to a file
node src/index.js <folder> --json             # machine-readable JSON
```
Exit code is **1** when a Critical/High is confirmed — drop it straight into CI.

### Mode 1 — scan a live URL (passive)
```bash
node src/index.js --url https://example.com
```

### Quick examples
```bash
node src/index.js tests/fixtures/vuln
node src/index.js tests/fixtures/gqltrpc
```

---

## 5. Run the tests

```bash
npm test
```

Expected: **20 passing, 0 failing** (~2s). What they cover:

- All 9 Mode 2 detector classes fire on vulnerable fixtures, stay silent on clean ones.
- Interprocedural taint: cross-file, cross-function, relative-path regression.
- Framework sources: Express/NestJS/Next.js, GraphQL/tRPC/TypeGraphQL, inline-resolver→helper.
- Mode 1: vulnerable local server lights up, secure one stays clean.

---

## 6. Reading the results

Findings land in three buckets:

- **Confirmed** — proven. Either a runnable check fired (secrets format, weak-crypto digest) or intraprocedural/interprocedural taint provably reaches a dangerous sink. Ranked Critical → Low.
- **Unconfirmed** — detection matched but proof couldn't be auto-established. Architectural classes (BOLA, JWT, race conditions) live here **by design** — they need human verification and come with a reproduction path.
- **Positive Observations** — good patterns worth replicating (parameterized queries, bcrypt, HSTS, etc.).

Every confirmed finding includes: location, plain-English attacker impact, proof (fired test or repro steps), and a before/after remediation diff.

### What gets detected

**Mode 2 (code):** SQL injection, command injection, path traversal, hardcoded secrets, weak crypto (MD5/SHA1/ECB/`Math.random`), non-constant-time comparison, broken object-level authorization (IDOR), JWT flaws, race conditions (TOCTOU).

**Taint tracks input across** functions and files, seeded from: Express/Fastify/Koa `req`/`ctx`, NestJS `@Body`/`@Param`/…, Next.js `request.json()`/`searchParams.get()`, GraphQL resolver args, tRPC `input`, TypeGraphQL `@Arg`.

**Mode 1 (URL):** missing/weak security headers, insecure cookie flags, permissive CORS, version disclosure, mixed content, credentials over HTTP, secrets/tokens in URLs, exposed paths (`/.env`, `/.git`, …), directory listing, exposed source maps, verbose error leaks.

---

## 7. VS Code extension

```bash
code --install-extension "vscode-extension/white-hat-vscode-0.1.0.vsix"
```
If `code` isn't found: VS Code → `Cmd+Shift+P` → **Shell Command: Install 'code' command in PATH**, then rerun. Or Extensions panel → `⋯` → **Install from VSIX** → pick the `.vsix`.

Use: click the **White Hat shield** in the activity bar → enter a folder or URL → **Scan**. View Diff shows before/after; Apply writes safe fixes on click (advisory-only fixes are disabled).

---

## 8. Browser plugin (Mode 1, persistent side panel)

1. `chrome://extensions` → enable **Developer mode**.
2. **Load unpacked** → select the `browser-plugin/` folder.
3. Click the toolbar icon to open the side panel, then browse. Findings populate from real response headers + DOM + a targeted probe, and persist across navigation.

---

## 9. Project layout

```
src/            engine: walker, parser, callgraph (interprocedural taint),
                detectors/, proof harness, report, memory, mode1/ (URL scan)
demo/server.js  live web UI (npm run demo)
vscode-extension/  VS Code extension + packaged .vsix
browser-plugin/    Chrome MV3 plugin (Mode 1)
tests/          node --test suites + fixtures
```

---

## 10. Honest limitations

- Mode 2 targets **JS/TS**. Taint is flow-sensitive but **context-insensitive** and name/relative-import based for call resolution (ambiguous names are skipped, not guessed).
- Architectural classes (BOLA/JWT/TOCTOU) are heuristics → always Unconfirmed.
- Framework source detection covers common shapes; unusual wiring (assembled GraphQL resolver maps, aliased tRPC procedures) can be missed.
- "Proof" is executed only for secrets + weak crypto; injection classes are proven by taint reachability + a reproduction path, not an executed exploit.
- Mode 1 is strictly passive (no rate-limit timing, no GraphQL introspection probing). Only probe domains you're authorized to test.
```
