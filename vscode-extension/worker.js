"use strict";
// Runs analysis off the extension-host thread so the UI never blocks.
// Folder path -> Mode 2 static analysis. http(s):// target -> Mode 1 URL scan.
const { parentPort, workerData } = require("worker_threads");

(async () => {
  try {
    const engine = require(workerData.enginePath);
    let result;
    if (/^https?:\/\//i.test(workerData.target)) {
      result = await engine.scanUrl(workerData.target);
      if (result.error) throw new Error(result.error);
    } else {
      result = engine.analyze(workerData.target, workerData.memPath);
    }
    parentPort.postMessage({ ok: true, result });
  } catch (e) {
    parentPort.postMessage({ ok: false, error: e && e.stack ? e.stack : String(e) });
  }
})();
