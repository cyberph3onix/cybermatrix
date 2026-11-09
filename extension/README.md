# CyberMatrix link check (browser extension)

Check a link before you open it. Right-click a link → **Check link with CyberMatrix**, or press the toolbar button
to check the current page. The result (class and coverage) appears as a notification or in the popup, with a link
to the full report and its evidence.

Privacy: nothing is sent automatically. Only the link you choose goes to the CyberMatrix API you configure
(default `http://localhost:8000`). No browsing history, page content or cookies are read.

## Install (Chrome / Edge / Brave)

1. Start the stack: `docker compose up` (API on :8000, web app on :3000).
2. Open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked**, choose this `extension/` folder.
3. Optional: in the extension's **Settings**, point it at a hosted API; you'll be asked for permission for that host.

Plain JavaScript (Manifest V3), no build step. The extension never runs page scripts or downloads anything.
