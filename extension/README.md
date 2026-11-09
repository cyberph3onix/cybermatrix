# CyberMatrix link check (browser extension)

Check a link before you open it. Right-click a link → **Check link with CyberMatrix**, or press the toolbar button
to check the current page. The result (class and coverage) appears as a notification or in the popup, with a link
to the full report and its evidence.

**Screenshot check (popup).** Tick "Include a screenshot of this tab" before checking. The visible tab is captured
and sent with its address; an AI model reads which organisation the page shows (logo, heading) and the backend
compares that with the real domain (`PAGE.SCREENSHOT_BRAND_MISMATCH`). The image goes to the AI provider and is not
stored.

**Real-time protection (off by default).** Turn it on in **Settings**. Every page you open then gets a quick check
(`POST /quick-check`: URL structure, lookalike domains, Google Safe Browsing, OpenPhish and earlier CyberMatrix
reports). The server never fetches the page and stores nothing. A `high_risk` or `confirmed_malicious` page is
replaced by a warning before it loads, with **Go back**, **Run a full assessment** and **Open the page anyway**
(remembered for that site until the browser closes). A `suspicious` page gets an amber `!` badge. A quick check with
no findings is `inconclusive`, never "low risk": it is not a full assessment.

Privacy: with real-time protection off, nothing is sent automatically, only the link you choose. With it on, the
address of every page you open goes to the CyberMatrix API you configure (default `http://localhost:8000`). No page
content or cookies are read.

## Install (Chrome / Edge / Brave)

1. Start the stack: `docker compose up` (API on :8000, web app on :3000).
2. Open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked**, choose this `extension/` folder.
3. Optional: in the extension's **Settings**, point it at a hosted API (you'll be asked for permission for that host)
   and turn on real-time protection.

Plain JavaScript (Manifest V3), no build step. The extension never runs page scripts or downloads anything.
