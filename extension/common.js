// Shared by the popup and the service worker. Talks only to the CyberMatrix API you configure (default: local).
export const DEFAULTS = { api: "http://localhost:8000", app: "http://localhost:3000", realtime: false };

export const LABELS = {
  low_risk: ["Low risk", "#1b6b73"],
  suspicious: ["Suspicious", "#b7791f"],
  high_risk: ["High risk", "#c2410c"],
  confirmed_malicious: ["Confirmed malicious", "#9b1c2c"],
  inconclusive: ["Inconclusive", "#5b6672"],
};

export async function settings() {
  const s = await chrome.storage.sync.get(DEFAULTS);
  return { api: s.api.replace(/\/$/, ""), app: s.app.replace(/\/$/, ""), realtime: !!s.realtime };
}

export function checkable(url) {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

/** POST /assess then GET /reports/{id}. Returns {reportId, classification, reason, coverage, reportUrl}. */
export async function checkLink(url) {
  if (!checkable(url)) throw new Error("Only http and https links can be checked.");
  const { api, app } = await settings();
  const res = await fetch(`${api}/assess`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input: url, subject_type: "url" }),
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try { detail = (await res.json()).detail ?? detail; } catch { /* not JSON */ }
    throw new Error(typeof detail === "string" ? detail : `HTTP ${res.status}`);
  }
  const { report_id } = await res.json();
  const report = await (await fetch(`${api}/reports/${report_id}`)).json();
  return {
    reportId: report_id,
    classification: report.classification,
    reason: report.classification_reason,
    coverage: report.coverage?.percent,
    reportUrl: `${app}/report/${report_id}`,
  };
}

async function errorOf(res) {
  let detail = `HTTP ${res.status}`;
  try { detail = (await res.json()).detail ?? detail; } catch { /* not JSON */ }
  return new Error(typeof detail === "string" ? detail : `HTTP ${res.status}`);
}

/** POST /quick-check: no page fetch, nothing stored. Returns {classification, classification_reason, findings, ...}. */
export async function quickCheck(url) {
  const { api } = await settings();
  const res = await fetch(`${api}/quick-check`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw await errorOf(res);
  return res.json();
}

/** Full assessment plus the screenshot check. `dataUrl` comes from chrome.tabs.captureVisibleTab. */
export async function checkWithScreenshot(url, dataUrl) {
  const { api, app } = await settings();
  const blob = await (await fetch(dataUrl)).blob();
  const form = new FormData();
  form.append("file", blob, "screenshot.jpg");
  form.append("url", url);
  form.append("consent", "true");
  const res = await fetch(`${api}/assess/screenshot`, { method: "POST", body: form });
  if (!res.ok) throw await errorOf(res);
  const { report_id } = await res.json();
  const report = await (await fetch(`${api}/reports/${report_id}`)).json();
  return {
    reportId: report_id,
    classification: report.classification,
    reason: report.classification_reason,
    coverage: report.coverage?.percent,
    reportUrl: `${app}/report/${report_id}`,
  };
}

export const DANGER = new Set(["high_risk", "confirmed_malicious"]);
