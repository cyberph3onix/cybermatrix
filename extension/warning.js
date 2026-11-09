import { checkLink, LABELS } from "./common.js";

const $ = (id) => document.getElementById(id);
const tabId = new URLSearchParams(location.search).get("tab");
const key = `cm:warn:${tabId}`;
const saved = (await chrome.storage.session.get(key))[key];

if (!saved) {
  $("title").textContent = "Nothing to show";
  $("url").textContent = "This warning has expired. Go back and open the link again.";
} else {
  const { url, q } = saved;
  const [label] = LABELS[q.classification] ?? [q.classification];
  $("title").textContent = `${label}: this page looks dangerous`;
  $("url").textContent = url;
  $("reason").textContent = q.classification_reason;
  for (const f of q.findings.slice(0, 6)) {
    const li = document.createElement("li");
    li.textContent = `${f.title} (${f.check_id})`;
    $("findings").append(li);
  }
  $("note").textContent = q.note;

  $("go").addEventListener("click", async () => {
    await chrome.runtime.sendMessage({ type: "cm-allow", url });
    location.replace(url);
  });
  $("report").addEventListener("click", async () => {
    $("report").disabled = true;
    $("out").textContent = "Running a full assessment (up to a minute)…";
    try {
      const r = await checkLink(url);
      location.assign(r.reportUrl);
    } catch (e) {
      $("out").textContent = `Couldn't assess: ${e.message || e}`;
      $("report").disabled = false;
    }
  });
}

$("back").addEventListener("click", () => {
  // If "back" lands on the blocked page again, real-time protection simply shows this warning again.
  if (history.length > 1) history.back();
  else location.replace("about:blank");
});
