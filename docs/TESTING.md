# Testing

## Automated (offline, no keys needed)

```bash
cd backend && uv run pytest -q          # 463 tests, ~7 s; live tests are deselected by default
cd backend && uv run ruff check app tests demo
cd contracts && forge test -vv          # 61 tests, 100% branch coverage
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
| `www.incometax.gov.in` | Low risk: a real-brand login page on the official domain is not flagged |
| `bit.ly/…` → `www.amazon.in` | Low risk: the shortener is expanded and the destination checked |
| Genuine HDFC OTP SMS | Not flagged: "do not share this OTP" is a warning, not a request |
| Scam SMS linking to the first | Message path: redaction, language signals, link assessed through the URL pipeline |

Each report says in its limitations that the data is recorded. `tests/test_demo_seed.py` keeps this story from rotting.

## Testing report: observed results

### URLs and messages (demo seed, real pipeline, recorded network data)

Produced by `python -m demo.seed`; `tests/test_demo_seed.py` asserts every row below.

| Case | Expected | Observed | Coverage | Confidence | Check IDs that fired |
|---|---|---|---|---|---|
| `paypa1-secure-login.xyz/signin` (fake PayPal login, listed by Safe Browsing) | malicious | `confirmed_malicious` (R1) | 90% | high | URL.INTEL.GSB, URL.LOOKALIKE.TYPOSQUAT, PAGE.CREDENTIAL_FORM, DOMAIN.YOUNG, TLS.CERT_VERY_NEW, DOMAIN.SUSPICIOUS_TLD, URL.KEYWORDS |
| `paypa1-verify-account.top` (same kit, not yet listed) | suspicious or worse | `suspicious` (R3) | 90% | high | URL.LOOKALIKE.TYPOSQUAT, PAGE.CREDENTIAL_FORM, DOMAIN.YOUNG, CORR.SHARED_INFRA, TLS.CERT_VERY_NEW, … |
| `esign-verify.in` (chain through the real eMudhra EM EV TLS CA - G3B) | malicious | `confirmed_malicious` (R1) | 90% | high | TLS.DISTRUSTED_CA, TLS.UNTRUSTED_ROOT, TLS.INCOMPLETE_CHAIN, URL.KEYWORDS |
| Scam SMS: "PayPal alert… card number and the OTP… <link>" | malicious | `confirmed_malicious` (R1 via its link) | 65% | medium | URL.INTEL.GSB (link), MSG.CREDENTIAL_REQUEST, MSG.SCAM_PATTERN, MSG.URGENCY, … |
| `www.sbi.co.in` (bank, page mentions logins) | not flagged | `low_risk` (R5) | 90% | high | none |
| `www.incometax.gov.in` (real-brand login page on the official domain) | not flagged | `low_risk` (R5) | 90% | high | none |
| `bit.ly/…` → `www.amazon.in` (shortener to an allowlisted shop) | not flagged | `low_risk` (R5) | 90% | high | URL.SHORTENER (low) |
| Genuine HDFC OTP SMS ("…Do not share this OTP with anyone") | not flagged | `inconclusive` (R4: AI step off in the seed) | 40% | low | MSG.AUTHORITY_IMPERSONATION (low) |

The real OTP SMS used to come out `suspicious` because "Do not share this OTP" matched as a request for it. Negated
phrases no longer count (`tests/test_message.py::test_safety_warning_is_not_a_credential_request`).

### Message analysis on ScamShield-IN

`uv run python -m eval.scamshield` (deterministic checks only, offline; links get the structure and lookalike
checks). "Flagged" = `suspicious` or worse; a legitimate message that is `low_risk` or `inconclusive` is not flagged.

**Sample (55 messages, hand-verified):** 25 fraud and 25 legit from ScamShield-IN (openrail), plus 5 legitimate bank,
shop and utility notices written in real formats, because the corpus has no modern bank alerts. Rows whose label looked
wrong on reading were not sampled. Result: 25/25 fraud flagged, 0/30 legit flagged. **This sample was used to tune the
rules, so it is a regression test (`test_eval_sample_stays_accurate`), not a measure of accuracy.**

**Held-out (every other labelled row, 528 messages, never read while tuning):**
`uv run python -m eval.scamshield --corpus sms_fraud_classification.json`

| Fraud type | Flagged |
|---|---|
| KYC scam | 7/7 |
| OTP phishing | 4/4 |
| UPI request scam | 5/5 |
| Fake police/court notice | 5/5 |
| Lottery/prize | 3/3 |
| Job scam | 3/3 |
| Loan scam | 2/2 |
| Investment scam | 4/5 |
| Insurance scam | 3/4 |
| **All specific scam types** | **36/38 (95%)** |
| "Generic Promo Fraud" | 4/66 |

Legitimate messages flagged: **9/424 (2.1%)**. Most of those are "free gift, just pay ₹399 delivery charges" offers that
we would call scams too, plus one private-IP link (`URL.IP_HOST`).

"Generic Promo Fraud" is mostly ordinary 2010 marketing (property ads, quizzes, even an anti-fraud tip) and we do not
try to flag it. The two missed scams use one tactic and a link ("car insurance expired, renew now: <domain>"). The LLM
language signals (`--llm`) are meant to catch those. Wording alone never goes above `suspicious` (heuristic cap).

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
- A registered link report: "Version history" lists v1. "Re-assess and register a new version" opens v2; v1 now shows
  Superseded and links forward. "Dispute this report" with MetaMask on Sepolia: the wallet asks for the 0.001 ETH bond,
  and after mining the report shows Disputed with the (masked) reason.
