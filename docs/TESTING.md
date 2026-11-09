# Testing

## Automated (offline, no keys needed)

```bash
cd backend && uv run pytest -q          # 441 tests, ~6 s; live tests are deselected by default
cd backend && uv run ruff check app tests demo
cd contracts && forge test -vv          # 46 tests, 100% branch coverage
uv run --no-project --with-requirements verify/requirements.txt --with pytest pytest verify/tests -q
cd frontend && npx tsc --noEmit && npm run lint
```

Tests use recorded fixtures, never live phishing URLs (they die). `tests/test_attacker_review.py` holds the
hostile-reviewer cases (SSRF encodings, malformed input, PII redaction, LLM and page-text injection, abuse limits).
The suite runs against SQLite; two bugs only Postgres showed (enum values stored as `RiskClass.X`, NUL bytes) now have
regression tests, but run the stack on Postgres before a demo.

## Live checks (need the keys in `.env`)

`GEMINI_API_KEY`, `GSB_API_KEY`, `VT_API_KEY`, `URLHAUS_AUTH_KEY` (and optionally `CERTSPOTTER_API_KEY`, which only
raises the Certificate Transparency rate limit). Without a key the matching check reports `unavailable` and
coverage drops; nothing breaks.

```bash
cd backend && uv run pytest -q -m live          # TLS and CT tests against badssl.com and crt.sh
# Threat-intel and Gemini calls have no automated live test: assess the known-bad URL below and check coverage
```

Known-bad test URL for demos: `https://testsafebrowsing.appspot.com/s/phishing.html` (Google's own test page).
Free Gemini tiers are small (the default `gemini-2.5-flash-lite`; plain 2.5 Flash allows ~20 requests/day). When the
quota runs out the AI parts show as unavailable and everything else keeps working.

## The demo (no network, no scam sites)

Scam domains die, DNS for invented ones doesn't resolve, and live feeds change. For a repeatable demo, load reports
built from recorded data through the real pipeline:

```bash
docker compose up -d postgres backend frontend
cd backend && DATABASE_URL=postgresql+asyncpg://cybermatrix:cybermatrix@localhost:5432/cybermatrix \
    uv run python -m demo.seed
```

| Report | Shows |
|---|---|
| `paypa1-secure-login.xyz` | Confirmed malicious: lookalike, credential form, 3-day-old domain, Safe Browsing hit |
| `paypa1-verify-account.top` | Suspicious: same certificate as the first, so it clusters; graded, not all-or-nothing |
| `esign-verify.in` | Confirmed malicious by `TLS.DISTRUSTED_CA`: the real eMudhra intermediate (public certificate; nothing is ever signed with its key) |
| `www.sbi.co.in` | Low risk with 90% coverage and a full limitations list: the best a result can be |
| Scam SMS linking to the first | Message path: redaction, language signals, link assessed through the URL pipeline |

Each report says in its limitations that the data is recorded. `tests/test_demo_seed.py` keeps this story from rotting.

## On-chain

Read-only checks cost nothing and send nothing:

```bash
python verify/verify.py --report backend/tests/fixtures/sample_report.json --rpc $SEPOLIA_RPC_URL --address $REGISTRY_ADDRESS   # MATCH
```

Change one character in the file and it reports `MISMATCH` (hash not registered). The `/verify` page does the same
for an uploaded file, hashing in the browser.

`docker compose` runs the backend with chain writes **off**. To demo read-only verification set only
`CHAIN_SEPOLIA_RPC_URL`. To allow "Register on-chain" set `CHAIN_RELAYER_PRIVATE_KEY` as well; that sends a real
Sepolia transaction from the relayer wallet (check it has Sepolia ETH first: a registration costs a tiny fraction of
0.001 ETH).

## Real phone

Automated width checks (below) catch layout bugs but not touch, keyboard or browser quirks. To try it on a phone on the
same Wi-Fi, find the computer's LAN address (`hostname -I`) and tell both containers about it:

```bash
LAN=192.168.1.23    # your address
PUBLIC_API_URL=http://$LAN:8000 CORS_ORIGINS=http://$LAN:3000 docker compose up -d --build
# phone: http://192.168.1.23:3000   (the OS firewall must allow ports 3000 and 8000)
```

`PUBLIC_API_URL` is baked into the frontend at build time, hence `--build`. Plain HTTP is fine for this check; the
camera/QR flow uses file upload, not live camera, so it doesn't need HTTPS.

Checked so far (Chrome, iframes at 320, 360, 375 and 412 px, on all 8 page types): no horizontal overflow, inputs at
16 px (iOS doesn't zoom), nav and buttons at least 44 px tall. Not checked on a physical device.

## Browser checklist (done by hand; re-run before the demo)

- Home: type a link, a message, an email; the Investigate button must not move while you type.
- Upload a QR image with a link, and one with a `upi://pay?pa=...` payload (inconclusive, with payee advice).
- `/verify`: look up a report ID, upload `sample_report.json` (MATCH), upload an edited copy (MISMATCH).
- A report page at 390 px wide: no horizontal scroll, evidence expands, limitations visible.
- `/clusters`: cluster with an AI-written description labelled as such.
