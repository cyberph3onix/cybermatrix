// Shared by the popup and the service worker. Talks only to the CyberMatrix API you configure (default: local).
export const DEFAULTS = { api: "http://localhost:8000", app: "http://localhost:3000" };

export const LABELS = {
  low_risk: ["Low risk", "#1b6b73"],
  suspicious: ["Suspicious", "#b7791f"],
  high_risk: ["High risk", "#c2410c"],
  confirmed_malicious: ["Confirmed malicious", "#9b1c2c"],
  inconclusive: ["Inconclusive", "#5b6672"],
};

export async function settings() {
  const s = await chrome.storage.sync.get(DEFAULTS);
  return { api: s.api.replace(/\/$/, ""), app: s.app.replace(/\/$/, "") };
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
