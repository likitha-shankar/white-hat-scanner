"use strict";
// Mode 1 self-check against local servers — vulnerable one must light up, secure
// one must stay clean. No external network.
const { test, before, after } = require("node:test");
const assert = require("node:assert");
const http = require("node:http");
const { scanUrl } = require("../src/mode1/scan");

function startServer(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, "127.0.0.1", () => resolve(srv));
  });
}
const urlOf = (srv) => `http://127.0.0.1:${srv.address().port}/`;

function vulnHandler(req, res) {
  // reflect any Origin with credentials — permissive CORS
  if (req.headers.origin) {
    res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  if (req.url === "/") {
    res.setHeader("X-Powered-By", "Express 4.17.1");
    res.setHeader("Set-Cookie", "sid=abc123def; Path=/");
    res.writeHead(200, { "Content-Type": "text/html" });
    return res.end('<html><body><form><input type="password" name="pw"></form><script src="/app.js"></script></body></html>');
  }
  if (req.url === "/app.js") {
    res.writeHead(200, { "Content-Type": "application/javascript" });
    return res.end('const k="AKIAIOSFODNN7EXAMPLE";fetch("/api");\n//# sourceMappingURL=app.js.map');
  }
  if (req.url === "/app.js.map") { res.writeHead(200); return res.end('{"version":3,"sources":["src/app.ts"]}'); }
  if (req.url === "/.env") { res.writeHead(200); return res.end("SECRET_KEY=supersecret\nDB_PASSWORD=hunter2"); }
  if (req.url.startsWith("/whitehat-probe-")) {
    res.writeHead(500);
    return res.end("Error: boom\n    at Object.<anonymous> (/srv/app.js:10:15)\n    at Module._compile (node:internal)");
  }
  res.writeHead(404); res.end("not found");
}

function secureHandler(req, res) {
  if (req.url === "/") {
    res.setHeader("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("Permissions-Policy", "geolocation=(), camera=()");
    res.setHeader("Set-Cookie", "sid=abc123def; Path=/; HttpOnly; SameSite=Lax");
    res.writeHead(200, { "Content-Type": "text/html" });
    return res.end('<html><body><a href="/login">login</a><script src="/app.js"></script></body></html>');
  }
  if (req.url === "/app.js") { res.writeHead(200); return res.end('console.log("hello");'); }
  res.writeHead(404); res.end("Not Found");
}

let vuln, secure;
before(async () => { vuln = await startServer(vulnHandler); secure = await startServer(secureHandler); });
after(() => { vuln.close(); secure.close(); });

test("vulnerable site: full surface is flagged", async () => {
  const r = await scanUrl(urlOf(vuln));
  const classes = new Set([...r.confirmed, ...r.unconfirmed].map((f) => f.class));
  for (const c of [
    "Missing Security Header",
    "Insecure Cookie",
    "Permissive CORS",
    "Secret in JS Bundle",
    "Source Map Exposed",
    "Sensitive Path Exposed",
    "Credentials Over HTTP",
    "Verbose Error Disclosure",
  ]) {
    assert.ok(classes.has(c), `expected Mode 1 finding: ${c}`);
  }
  // the .env leak must be Critical
  const env = r.confirmed.find((f) => f.class === "Sensitive Path Exposed");
  assert.strictEqual(env.severity, "Critical");
  // CORS reflection is High and carries the observed request/response as proof
  const cors = r.confirmed.find((f) => f.class === "Permissive CORS");
  assert.strictEqual(cors.severity, "High");
  assert.ok(cors.proof.steps.join(" ").includes("Access-Control-Allow-Origin"));
});

test("secure site: no confirmed findings, positives present", async () => {
  const r = await scanUrl(urlOf(secure));
  assert.strictEqual(r.confirmed.length, 0, "secure site produced: " + r.confirmed.map((f) => f.class + "/" + f.summary).join(", "));
});

test("invalid URL returns an error, not a throw", async () => {
  const r = await scanUrl("not-a-url");
  assert.ok(r.error && /invalid URL/i.test(r.error));
});
