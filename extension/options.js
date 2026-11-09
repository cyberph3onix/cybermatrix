import { DEFAULTS, settings } from "./common.js";

const s = await settings();
document.getElementById("api").value = s.api;
document.getElementById("app").value = s.app;

document.getElementById("save").addEventListener("click", async () => {
  const api = document.getElementById("api").value.trim() || DEFAULTS.api;
  const app = document.getElementById("app").value.trim() || DEFAULTS.app;
  const msg = document.getElementById("msg");
  try {
    const origin = new URL(api).origin;
    if (!/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
      const ok = await chrome.permissions.request({ origins: [origin + "/*"] });
      if (!ok) throw new Error(`Permission to reach ${origin} was refused.`);
    }
    await chrome.storage.sync.set({ api, app });
    msg.textContent = "Saved.";
  } catch (e) {
    msg.textContent = String(e.message || e);
  }
});
