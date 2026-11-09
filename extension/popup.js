import { checkable, checkLink, checkWithScreenshot, LABELS } from "./common.js";

const $ = (id) => document.getElementById(id);
const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
const url = tab?.url ?? "";
$("url").textContent = url;
if (!checkable(url)) {
  $("go").disabled = true;
  $("out").textContent = "This page isn't an http(s) link.";
}

$("go").addEventListener("click", async () => {
  $("go").disabled = true;
  $("go").textContent = "Checking… (up to a minute)";
  $("out").replaceChildren();
  try {
    const r = $("shot").checked
      ? await checkWithScreenshot(url, await chrome.tabs.captureVisibleTab(tab.windowId, { format: "jpeg", quality: 80 }))
      : await checkLink(url);
    const [label, color] = LABELS[r.classification] ?? [r.classification, "#5b6672"];
    const box = document.createElement("div");
    box.className = "result";
    box.style.borderColor = color;
    const title = document.createElement("strong");
    title.textContent = `${label} · ${r.coverage}% of checks completed`;
    const reason = document.createElement("div");
    reason.className = "url";
    reason.textContent = r.reason;
    const link = document.createElement("a");
    link.href = r.reportUrl;
    link.target = "_blank";
    link.textContent = "Open the full report with evidence";
    box.append(title, reason, link);
    $("out").append(box);
  } catch (e) {
    $("out").textContent = `Couldn't check: ${e.message || e}`;
  } finally {
    $("go").disabled = false;
    $("go").textContent = "Check again";
  }
});
