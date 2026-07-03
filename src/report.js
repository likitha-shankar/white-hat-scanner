"use strict";
// Renders the findings report (markdown) in the spec's 3-section format.
const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4 };

function fenceDiff(before, after) {
  const del = String(before).split("\n").map((l) => "- " + l);
  const add = String(after).split("\n").map((l) => "+ " + l);
  return "```diff\n" + del.concat(add).join("\n") + "\n```";
}

function sortFindings(list) {
  return [...list].sort((a, b) => {
    if (a.known !== b.known) return a.known ? -1 : 1; // known patterns first
    return (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
  });
}

function renderFinding(f, idx) {
  const id = "WHT-" + String(idx + 1).padStart(3, "0");
  const proof =
    f.proof.kind === "runnable"
      ? `Runnable test ${f.proven ? "**fired**" : "did not fire"}:\n\n\`\`\`\n${f.proofOutput || ""}\n\`\`\``
      : "Reproduction steps:\n" + f.proof.steps.map((s, i) => `  ${i + 1}. ${s}`).join("\n");

  return [
    `### ${id} — ${f.class} (${f.severity})${f.known ? "  · _known pattern_" : ""}`,
    `**Location:** \`${f.rel}:${f.line}\`  · unit: _${f.unit}_`,
    `**Summary:** ${f.summary}`,
    `**Impact:** ${f.attackerImpact}`,
    `**Proof:** ${proof}`,
    `**Remediation:**\n\n${fenceDiff(f.remediation.before, f.remediation.after)}`,
    `_Contract preserved:_ ${f.remediation.contract}`,
  ].join("\n\n");
}

function render({ confirmed, unconfirmed, positives, knownClasses, stats }) {
  const out = [];
  out.push(`# White Hat Findings Report`);
  const scanned =
    stats.mode === "url"
      ? `Scanned **${stats.url}** (${stats.requests} requests).`
      : `Scanned **${stats.files}** files across **${stats.units}** logical units.`;
  out.push(`${scanned} **${confirmed.length}** confirmed, **${unconfirmed.length}** unconfirmed.`);

  out.push(`\n## Section 1 — Confirmed Findings`);
  if (!confirmed.length) out.push("_None._");
  sortFindings(confirmed).forEach((f, i) => out.push(renderFinding(f, i)));

  out.push(`\n## Section 2 — Unconfirmed Findings`);
  out.push("_Require manual verification — detection matched but proof could not be automatically established._");
  if (!unconfirmed.length) out.push("_None._");
  sortFindings(unconfirmed).forEach((f, i) => out.push(renderFinding(f, i + confirmed.length)));

  out.push(`\n## Section 3 — Positive Security Observations`);
  if (!positives.length) out.push("_No notable good patterns detected._");
  else positives.forEach((p) => out.push(`- **${p.label}** — e.g. \`${p.rel}\`. Replicate this elsewhere.`));

  if (knownClasses && knownClasses.size)
    out.push(`\n_Memory: checked ${knownClasses.size} known pattern class(es) first._`);

  return out.join("\n\n") + "\n";
}

module.exports = { render, fenceDiff };
