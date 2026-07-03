"use strict";
// Copies the engine (../src) into ./engine so the packaged .vsix is self-contained.
// Runs automatically before vsce package (vscode:prepublish). Babel deps resolve
// from this extension's own node_modules.
const fs = require("fs");
const path = require("path");

const from = path.join(__dirname, "..", "src");
const to = path.join(__dirname, "engine");

function copyDir(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  for (const e of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, e.name), d = path.join(dst, e.name);
    if (e.isDirectory()) copyDir(s, d);
    else if (e.isFile()) fs.copyFileSync(s, d);
  }
}

fs.rmSync(to, { recursive: true, force: true });
copyDir(from, to);
console.log("bundled engine -> ./engine");
