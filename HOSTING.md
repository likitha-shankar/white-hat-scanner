# Hosting the live demo (free)

The web demo (`demo/server.js`) is a small Node HTTP server. For a **public** deployment
run it with `DEMO_SAFE=1`, which restricts scanning to the bundled sample projects — no
arbitrary filesystem paths and no arbitrary URLs, so there is no file-read or SSRF exposure.

## Option A — Render (recommended, free, no credit card)

This repo ships a `render.yaml` blueprint.

1. Sign in at https://render.com (GitHub login).
2. **New → Blueprint** → connect `likitha-shankar/white-hat-scanner`.
3. Render reads `render.yaml`, builds with `npm install`, starts with `node demo/server.js`,
   and sets `DEMO_SAFE=1` automatically.
4. You get a public URL like `https://white-hat-demo.onrender.com`.

Free web services sleep after ~15 min idle and cold-start on the next request (a few seconds).

## Option B — Railway / Glitch / Fly

Any host that runs a Node process works. Set:
- Build: `npm install`
- Start: `node demo/server.js`
- Env: `DEMO_SAFE=1` (required for a public instance)
- The server binds to `process.env.PORT` automatically.

## Option C — Local (full power, unrestricted)

```bash
npm run demo        # http://localhost:7777, scans any folder path or URL you type
```

Do **not** expose an unrestricted (`DEMO_SAFE` unset) instance to the internet — it would let
anyone read the host's files (Mode 2) or make it fetch arbitrary URLs (Mode 1).

## Note on the engine itself

The CLI engine and the VS Code extension are meant to run **locally** on a developer's machine
or in CI — they are not hosted services. Only the demo UI is deployable, and only in safe mode.
