import { checkLink, checkable, DANGER, LABELS, quickCheck, settings } from "./common.js";

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

// ---------- real-time protection (off unless enabled in Settings) ----------
// Every top-level navigation gets a quick check: URL structure, lookalikes, Safe Browsing, OpenPhish and earlier
// CyberMatrix reports. The page itself is never fetched by the server and nothing is stored. A high-risk page is
// replaced by a warning; a suspicious one gets an amber badge.

const ALLOWED = "cm:allowed"; // origins the user chose to open anyway, this browser session only

async function allowed(url) {
  const list = (await chrome.storage.session.get(ALLOWED))[ALLOWED] ?? [];
  return list.includes(new URL(url).origin);
}

function ownOrigin(url, s) {
  const o = new URL(url).origin;
  return o === new URL(s.api).origin || o === new URL(s.app).origin;
}

chrome.webNavigation.onBeforeNavigate.addListener(async ({ tabId, frameId, url }) => {
  if (frameId !== 0 || !checkable(url)) return;
  const s = await settings();
  if (!s.realtime || ownOrigin(url, s) || (await allowed(url))) return;
  let q;
  try {
    q = await quickCheck(url);
  } catch {
    q = { classification: "unreachable", classification_reason: "CyberMatrix couldn't check this page (server unreachable)." };
  }
  if (DANGER.has(q.classification)) {
    await chrome.storage.session.set({ [`cm:warn:${tabId}`]: { url, q } });
    chrome.tabs.update(tabId, { url: chrome.runtime.getURL(`warning.html?tab=${tabId}`) });
    return;
  }
  // The browser resets a tab's badge when the navigation commits (error pages included), which can happen before or
  // after this check returns. Remember the result and apply it now and again on commit.
  const badge = { url, classification: q.classification, reason: q.classification_reason };
  await chrome.storage.session.set({ [`cm:badge:${tabId}`]: badge });
  applyBadge(tabId, badge);
});

function applyBadge(tabId, { classification, reason }) {
  const [label, color] = LABELS[classification] ?? ["Not checked", "#5b6672"];
  chrome.action.setBadgeBackgroundColor({ tabId, color });
  chrome.action.setBadgeText({ tabId, text: { suspicious: "!", unreachable: "?" }[classification] ?? "" });
  chrome.action.setTitle({ tabId, title: `CyberMatrix quick check: ${label}. ${reason}` });
}

async function reapply({ tabId, frameId, url }) {
  if (frameId !== 0) return;
  const key = `cm:badge:${tabId}`;
  const b = (await chrome.storage.session.get(key))[key];
  if (b && b.url === url) applyBadge(tabId, b);
}
chrome.webNavigation.onCommitted.addListener(reapply);
chrome.webNavigation.onErrorOccurred.addListener(reapply); // e.g. "site can't be reached"

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (msg?.type === "cm-allow" && checkable(msg.url)) {
    chrome.storage.session.get(ALLOWED).then(async (got) => {
      const list = new Set(got[ALLOWED] ?? []);
      list.add(new URL(msg.url).origin);
      await chrome.storage.session.set({ [ALLOWED]: [...list] });
      reply({ ok: true });
    });
    return true; // async reply
  }
  return false;
});
