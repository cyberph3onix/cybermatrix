import { checkLink, LABELS } from "./common.js";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "cm-check-link", title: "Check link with CyberMatrix", contexts: ["link"] });
  chrome.contextMenus.create({ id: "cm-check-page", title: "Check this page with CyberMatrix", contexts: ["page"] });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const url = info.menuItemId === "cm-check-link" ? info.linkUrl : tab?.url;
  if (!url) return;
  notify("cm-busy", "Checking…", url);
  try {
    const r = await checkLink(url);
    const [label] = LABELS[r.classification] ?? [r.classification];
    await chrome.storage.session.set({ [`cm:${r.reportId}`]: r.reportUrl });
    notify(`cm:${r.reportId}`, `${label} (${r.coverage}% of checks completed)`, `${url}\nClick for the full report.`);
  } catch (e) {
    notify("cm-error", "Couldn't check this link", String(e.message || e));
  }
});

chrome.notifications.onClicked.addListener(async (id) => {
  const url = (await chrome.storage.session.get(id))[id];
  if (url) chrome.tabs.create({ url });
});

function notify(id, title, message) {
  chrome.notifications.create(id, { type: "basic", iconUrl: "icon.png", title, message: message.slice(0, 300) });
}
