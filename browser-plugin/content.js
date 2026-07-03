"use strict";
// Content script: analyzes the live DOM and same-origin scripts (from browser
// cache — no extra fetch beyond re-reading already-loaded assets), then reports
// to the service worker. No page code is executed.
(async () => {
  const url = location.href;
  const isHttps = location.protocol === "https:";
  let findings = WH.domFindings(document, url, isHttps);

  // inline scripts — scan text directly, no network
  for (const el of document.querySelectorAll("script:not([src])")) {
    findings = findings.concat(WH.scanScript(el.textContent || "", url + " (inline)"));
  }

  // same-origin external scripts — re-read (cache hit) to scan for secrets + maps
  const srcs = [...document.scripts]
    .map((s) => s.src)
    .filter(Boolean)
    .filter((s) => { try { return new URL(s).origin === location.origin; } catch { return false; } })
    .slice(0, 6);

  for (const s of srcs) {
    try {
      const txt = (await (await fetch(s)).text()).slice(0, 500000);
      findings = findings.concat(WH.scanScript(txt, s));
      const mapRef = WH.sourceMapUrl(txt);
      if (mapRef) {
        const mapUrl = new URL(mapRef, s).toString();
        const mres = await fetch(mapUrl);
        if (mres.status === 200)
          findings.push(WH.mk("Source Map Exposed", "Medium", "JavaScript source map is publicly accessible",
            "The .map file reconstructs original source, revealing internal logic, comments, and paths.",
            `${mapUrl} returns 200`, "Do not deploy .map files to production", [`GET ${mapUrl}`, "HTTP 200"]));
      }
    } catch (_) {}
  }

  chrome.runtime.sendMessage({ type: "dom", url, findings });
})();
