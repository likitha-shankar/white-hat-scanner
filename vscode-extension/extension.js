"use strict";
// White Hat VS Code extension. Sidebar webview drives a worker-thread scan of the
// engine (Mode 2), shows a ranked findings report, opens a native before/after
// diff per finding, and applies safe remediations only on explicit click.
const vscode = require("vscode");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { Worker } = require("worker_threads");

const findingsById = new Map();
let scanRoot = null;

// Virtual documents backing the native diff viewer (scheme: whitehat:).
const diffContent = new Map();
const contentProvider = {
  provideTextDocumentContent(uri) {
    return diffContent.get(uri.toString()) || "";
  },
};

class Provider {
  constructor(context) {
    this.context = context;
  }

  resolveWebviewView(view) {
    this.view = view;
    view.webview.options = { enableScripts: true };
    view.webview.html = html(view.webview);
    view.webview.onDidReceiveMessage((m) => {
      if (m.type === "scan") this.scan(m.path);
      else if (m.type === "diff") this.diff(m.id);
      else if (m.type === "apply") this.apply(m.id);
    });
  }

  post(msg) {
    if (this.view) this.view.webview.postMessage(msg);
  }

  scan(input) {
    const folders = vscode.workspace.workspaceFolders;
    scanRoot =
      input && input.trim()
        ? input.trim()
        : folders && folders[0]
        ? folders[0].uri.fsPath
        : null;
    if (!scanRoot) {
      this.post({ type: "error", message: "No folder to scan. Open a project or enter a path." });
      return;
    }
    this.post({ type: "status", message: "Scanning " + scanRoot + " …" });

    const cfg = vscode.workspace.getConfiguration("whiteHat");
    const bundled = path.join(this.context.extensionPath, "engine", "index.js");
    const dev = path.join(this.context.extensionPath, "..", "src", "index.js");
    const enginePath = cfg.get("enginePath") || (fs.existsSync(bundled) ? bundled : dev);

    let worker;
    try {
      worker = new Worker(path.join(this.context.extensionPath, "worker.js"), {
        workerData: {
          enginePath,
          target: scanRoot,
          memPath: path.join(scanRoot, "white_hat_memory.md"),
        },
      });
    } catch (e) {
      this.post({ type: "error", message: "Failed to start scan: " + e.message });
      return;
    }
    worker.on("message", (msg) => {
      if (!msg.ok) this.post({ type: "error", message: msg.error });
      else this.ingest(msg.result);
      worker.terminate();
    });
    worker.on("error", (e) => this.post({ type: "error", message: e.message }));
  }

  ingest(r) {
    findingsById.clear();
    const tag = (arr, section) =>
      arr.map((f, i) => {
        const id = "WHT-" + String(i + 1).padStart(3, "0") + "-" + section;
        const applyable = !!(f.remediation && f.remediation.applyable);
        findingsById.set(id, { ...f, id, section, applyable });
        return {
          id,
          applyable,
          class: f.class,
          severity: f.severity,
          rel: f.rel,
          line: f.line,
          summary: f.summary,
          impact: f.attackerImpact,
          proof: f.proof,
          proven: f.proven,
          proofOutput: f.proofOutput,
          known: f.known,
        };
      });
    this.post({
      type: "results",
      confirmed: tag(r.confirmed, "c"),
      unconfirmed: tag(r.unconfirmed, "u"),
      positives: r.positives || [],
      stats: r.stats || {},
    });
  }

  async diff(id) {
    const f = findingsById.get(id);
    if (!f || !f.remediation) return;
    const left = vscode.Uri.parse("whitehat:" + encodeURIComponent(id) + "/before.js");
    const right = vscode.Uri.parse("whitehat:" + encodeURIComponent(id) + "/after.js");
    diffContent.set(left.toString(), f.remediation.before || "");
    diffContent.set(right.toString(), f.remediation.after || "");
    await vscode.commands.executeCommand(
      "vscode.diff",
      left,
      right,
      `${f.class} — ${f.rel}:${f.line} (before ⟷ after)`
    );
  }

  async apply(id) {
    const f = findingsById.get(id);
    if (!f || !f.applyable) return;
    const abs = path.isAbsolute(f.rel) ? f.rel : path.join(scanRoot, f.rel);
    const uri = vscode.Uri.file(abs);
    let doc;
    try {
      doc = await vscode.workspace.openTextDocument(uri);
    } catch {
      vscode.window.showWarningMessage("White Hat: cannot open " + f.rel);
      return;
    }
    const before = f.remediation.before;
    const idx = doc.getText().indexOf(before);
    if (idx < 0) {
      vscode.window.showWarningMessage(
        `White Hat: source for ${id} changed since scan — apply manually from the diff.`
      );
      return;
    }
    const range = new vscode.Range(doc.positionAt(idx), doc.positionAt(idx + before.length));
    const edit = new vscode.WorkspaceEdit();
    edit.replace(uri, range, f.remediation.after);
    const ok = await vscode.workspace.applyEdit(edit);
    if (ok) {
      await doc.save();
      this.post({ type: "applied", id });
      vscode.window.showInformationMessage(`White Hat: applied ${id} in ${f.rel}`);
    }
  }
}

function html(webview) {
  const nonce = crypto.randomBytes(16).toString("hex");
  const csp = `default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';`;
  return `<!DOCTYPE html><html><head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<style>
  body { font-family: var(--vscode-font-family); font-size: 12px; padding: 8px; }
  input { width: 100%; box-sizing: border-box; padding: 4px; margin-bottom: 6px;
    background: var(--vscode-input-background); color: var(--vscode-input-foreground);
    border: 1px solid var(--vscode-input-border); }
  button { cursor: pointer; border: none; padding: 4px 8px; border-radius: 3px;
    background: var(--vscode-button-background); color: var(--vscode-button-foreground); }
  button.secondary { background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground); }
  button:disabled { opacity: .5; cursor: default; }
  .card { border-left: 3px solid #888; padding: 6px 8px; margin: 6px 0;
    background: var(--vscode-editorWidget-background); border-radius: 3px; }
  .Critical { border-color: #e51400; } .High { border-color: #f7630c; }
  .Medium { border-color: #d7a500; } .Low { border-color: #3794ff; }
  .badge { font-weight: 600; font-size: 10px; padding: 1px 5px; border-radius: 8px; color: #fff; }
  .b-Critical { background:#e51400; } .b-High { background:#f7630c; } .b-Medium { background:#d7a500; } .b-Low { background:#3794ff; }
  .loc { color: var(--vscode-descriptionForeground); font-family: var(--vscode-editor-font-family); }
  .impact { color: var(--vscode-descriptionForeground); margin: 4px 0; }
  .row { display: flex; gap: 6px; margin-top: 4px; }
  h3 { margin: 12px 0 4px; } .known { color: var(--vscode-charts-yellow); }
  .muted { color: var(--vscode-descriptionForeground); }
</style></head><body>
<input id="path" placeholder="Folder path or https:// URL (blank = workspace root)">
<button id="scan">Scan</button>
<div class="muted" style="margin:2px 0 6px">Folder → code analysis · URL → live surface scan</div>
<div id="status" class="muted"></div>
<div id="out"></div>
<script nonce="${nonce}">
const vs = acquireVsCodeApi();
const $ = (id) => document.getElementById(id);
$("scan").onclick = () => { $("status").textContent = "Starting…"; vs.postMessage({ type:"scan", path: $("path").value }); };

function esc(s){ return String(s==null?"":s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

function card(f){
  const proof = f.proof && f.proof.kind === "runnable"
    ? "Runnable proof: " + (f.proven ? "fired ✓" : "not fired") + (f.proofOutput ? " — " + esc(f.proofOutput) : "")
    : "Repro: " + (f.proof && f.proof.steps ? esc(f.proof.steps.join("  •  ")) : "manual");
  return '<div class="card ' + f.severity + '">'
    + '<span class="badge b-' + f.severity + '">' + f.severity + '</span> '
    + '<b>' + esc(f.class) + '</b>' + (f.known ? ' <span class="known">· known</span>' : '')
    + '<div class="loc">' + esc(f.rel) + ':' + f.line + '</div>'
    + '<div>' + esc(f.summary) + '</div>'
    + '<div class="impact">' + esc(f.impact) + '</div>'
    + '<div class="muted">' + proof + '</div>'
    + '<div class="row">'
    + '<button class="secondary" data-diff="' + f.id + '">View Diff</button>'
    + '<button data-apply="' + f.id + '" ' + (f.applyable ? '' : 'disabled title="Advisory — apply manually from the diff"') + '>Apply</button>'
    + '</div></div>';
}

function render(m){
  let h = '<div class="muted">' + (m.stats.files||0) + ' files · ' + (m.stats.units||0) + ' units · '
    + m.confirmed.length + ' confirmed · ' + m.unconfirmed.length + ' unconfirmed</div>';
  h += '<h3>Confirmed (' + m.confirmed.length + ')</h3>' + (m.confirmed.map(card).join("") || '<div class="muted">None</div>');
  h += '<h3>Unconfirmed (' + m.unconfirmed.length + ')</h3><div class="muted">Manual verification.</div>'
    + (m.unconfirmed.map(card).join("") || '<div class="muted">None</div>');
  h += '<h3>Positive Observations</h3>' + (m.positives.length
    ? '<ul>' + m.positives.map(p => '<li>' + esc(p.label) + ' — <span class="loc">' + esc(p.rel) + '</span></li>').join("") + '</ul>'
    : '<div class="muted">None detected</div>');
  $("out").innerHTML = h;
  document.querySelectorAll("[data-diff]").forEach(b => b.onclick = () => vs.postMessage({ type:"diff", id: b.getAttribute("data-diff") }));
  document.querySelectorAll("[data-apply]").forEach(b => b.onclick = () => vs.postMessage({ type:"apply", id: b.getAttribute("data-apply") }));
}

window.addEventListener("message", e => {
  const m = e.data;
  if (m.type === "status") $("status").textContent = m.message;
  else if (m.type === "error") $("status").textContent = "Error: " + m.message;
  else if (m.type === "results") { $("status").textContent = "Done."; render(m); }
  else if (m.type === "applied") { const b = document.querySelector('[data-apply="' + m.id + '"]'); if (b){ b.disabled = true; b.textContent = "Applied ✓"; } }
});
</script></body></html>`;
}

function activate(context) {
  const provider = new Provider(context);
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider("whiteHat.findings", provider),
    vscode.workspace.registerTextDocumentContentProvider("whitehat", contentProvider),
    vscode.commands.registerCommand("whiteHat.scan", () => provider.scan())
  );
}

function deactivate() {}

module.exports = { activate, deactivate };
