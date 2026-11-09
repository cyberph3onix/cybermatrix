# CyberMatrix

**Paste a link, domain, email, message or QR code and get an evidence-based risk assessment, never a bare "safe"; then
commit the report's hash to a blockchain registry that anyone can verify without trusting us.**

## Problem

Phishing and scam messages (fake KYC, UPI collect requests, bank and exam-portal lookalikes, "customer care" calls)
reach people faster than blocklists update. Existing checkers answer "safe / unsafe" with no reasons, so users can't
judge the answer, a clean result is read as a guarantee, and AI-only tools can be talked into the wrong verdict.
Threat reports from individuals also can't be trusted or shared without exposing the victim's data.

## Solution

- **Evidence first.** Deterministic checks produce every finding (URL and lookalike analysis, redirect chain, page
  forms, TLS chain, revocation, Certificate Transparency, a curated distrust list, RDAP/DNS, Google Safe Browsing,
  URLhaus, OpenPhish, VirusTotal). Each finding shows its source, strength, impact, remediation and limitations.
- **Fixed rules decide.** Rules R1–R5 (`docs/RISK_ENGINE.md`) set the class: `confirmed_malicious`, `high_risk`,
  `suspicious`, `inconclusive` or `low_risk`, with a score, coverage and confidence. The best result is "no significant
  indicators within the checks performed", never "safe".
- **AI, bounded.** The LLM explains findings and flags scam wording. Its input is redacted and wrapped as untrusted, its
  output is schema-checked, its signals are capped as heuristic, and prompt injection is flagged and cannot change
  the class.
- **TLS trust.** Flags the compromised eMudhra intermediates by certificate *and* public-key hash (catches
  cross-signs) and gives the certificate its own verdict. It does not claim to detect a CA's key-generation weakness
  from a URL.
- **Messages and correlation.** Extracts links, phones, UPI IDs and wallets; every link runs through the full
  pipeline; related reports cluster with the shared indicator shown for each link.
- **Security posture** (headers, cookies, CORS, old TLS, known-vulnerable JS libraries via OSV) is reported
  separately and never changes the phishing class.
- **Web3 registry.** Only a salted hash goes on-chain (Sepolia). Revisions, bonded disputes and validator status are
  on-chain; `verify.py` checks any report independently.

## Demo links and a screenshot

| | |
|---|---|
| Live site | _filled at submission (Render)_. Free tier: the first request after idle takes about a minute |
| Demo video | _filled at submission (YouTube)_ |
| Testing report | [`docs/TESTING.md`](docs/TESTING.md) (observed results, raw data in [`docs/evidence/`](docs/evidence/)) |
| Compliance matrix | [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) |

![Report page: confirmed malicious via a distrusted eMudhra intermediate, with score, confidence, timestamp, coverage and the rule that decided](docs/img/report-emudhra.jpg)

Safe demo inputs: `https://www.sbi.co.in/` (low risk), Google's Safe Browsing test page
`hxxps://testsafebrowsing[.]appspot[.]com/s/phishing.html` (confirmed malicious), `https://expired.badssl.com/`
(expired certificate), and the recorded fixtures loaded by `python -m demo.seed` (eMudhra chain, a PayPal-lookalike
kit, a genuine OTP SMS). No live phishing sites are used.

### On-chain registry (Sepolia)

| | |
|---|---|
| Contract (v3) | [`0x5De4Cd6F651A4D80ddA16fc70431dd669621BeeA`](https://sepolia.etherscan.io/address/0x5de4cd6f651a4d80dda16fc70431dd669621beea#code) (source verified) |
| Deploy tx | [`0xbdf33b29…bb3b`](https://sepolia.etherscan.io/tx/0xbdf33b29c1e6d07e0eb41d5742d924f21444c5c1817857d3c1c77d4ca507bb3b), block 12099038 |
| Sample report registration | [`0x08d6c9ef…37c5`](https://sepolia.etherscan.io/tx/0x08d6c9ef458d86e87121774a2c57439855f76b8b918ab6275e4733aee44237c5) (report #1), validated in [`0xab1eef21…36c0`](https://sepolia.etherscan.io/tx/0xab1eef2179649bfc7f8d32d31b3594f9a4cad7d1c5806f24dc0714dfc05c36c0) |
| Dispute + resolution | report #2 disputed in [`0x2ac133a3…cd8a`](https://sepolia.etherscan.io/tx/0x2ac133a3678fd312b7d48de477e411346afa92f12c2bb0c763df5edafad0cd8a), validated in [`0x98b5683f…c7d8`](https://sepolia.etherscan.io/tx/0x98b5683ff793987e27041be7502791d3abb8e9cf5f6e21ebc335939e3752c7d8) |
| Dispute bond | 0.001 Sepolia ETH |

On-chain: report hash, parent hash, status, timestamp, reporter address (plus a dispute's reason hash and bond).
URLs, messages and personal data stay off-chain, and a random 32-byte salt in each report stops anyone guessing a
URL from its hash. Roles: the deployer is owner and the only validator; the backend relayer is the only authorised
reporter, so strangers can't register forged reports. Anyone can dispute from their own wallet by posting the bond;
the validator's ruling returns it (Rejected) or keeps it (Validated). Users can also sign a report with their own
wallet (EIP-712) to show who vouched for it. Details: [`contracts/deployments/sepolia.json`](contracts/deployments/sepolia.json).

A registry match proves the report hasn't changed since it was registered and shows its history. It does not prove
the report's conclusions are true.

## Tech stack

- **Backend:** Python 3.12, FastAPI, Pydantic v2, SQLAlchemy (async) + Postgres, httpx + httpx-secure (SSRF guard),
  sslyze + cryptography (TLS), dnstwist + Unicode confusables (lookalikes), tldextract, selectolax, Pillow + zxing-cpp
  (QR), rfc8785 + eth-hash + web3.py (hashing and registry).
- **AI:** Gemini Flash-Lite (or Claude Haiku as fallback) for explanations and wording signals only.
- **Threat intel:** Google Safe Browsing v5, URLhaus, OpenPhish, VirusTotal, Cert Spotter / crt.sh, RDAP, DNS-over-HTTPS,
  osv.dev.
- **Frontend:** Next.js 16, React 19, TypeScript, Tailwind CSS; types generated from the backend's OpenAPI schema.
- **Web3:** Solidity 0.8.24, Foundry, Sepolia, Etherscan verification.
- **Tests:** pytest (656 offline + 10 live), Foundry (70), verify tests (13).

## Architecture

```
 input (link | domain | email | message | QR image)
   ▼
 Submit ─► Investigate ───────────────────────────────► Analyse ──────► Assess risk ──► Report & verify
           safe_fetch: SSRF guard, pinned IP,          checks/* →       engine/risk     stored canonical JSON
           manual redirects ≤5, 2 MB, 5 s, no JS       Finding +        R1–R5, score,   AI explanation (redacted)
           messages: extract + redact indicators      Evidence +       coverage,       keccak256(RFC 8785)
           links in messages → full URL pipeline       strength         confidence      → ThreatRegistry (Sepolia)
           threat intel via fixed-host API client     correlation/*                    verify.py / /verify

 frontend (Next.js) ──HTTP──► backend (FastAPI) ──► Postgres
 verify/verify.py: report.json + RPC + address → MATCH / MISMATCH (no backend needed)
```

What is AI and what is deterministic: every finding, the class, score, coverage, correlation and every on-chain
action are deterministic code. The LLM writes the plain-language summary, can add *heuristic* wording signals
(capped at 30 points, so never above `suspicious` on their own), and reads the brand from an optional screenshot.

More: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (pipeline, threat-intel sources and what each one receives,
security methodology, known limitations), [`docs/RISK_ENGINE.md`](docs/RISK_ENGINE.md) (every check ID and rule),
[`docs/DECISIONS.md`](docs/DECISIONS.md) (library and source choices, with citations).

## Setup and run steps

```bash
git clone https://github.com/cyberph3onix/cybermatrix && cd cybermatrix
cp .env.example .env        # fill in what you have; a missing key makes that check "unavailable", nothing breaks
docker compose up --build   # frontend http://localhost:3000, backend http://localhost:8000 (OpenAPI at /docs)
```

Environment variable names (values never committed): `GEMINI_API_KEY` or `ANTHROPIC_API_KEY`, `GSB_API_KEY`,
`VT_API_KEY`, `URLHAUS_AUTH_KEY`, `CERTSPOTTER_API_KEY` (optional), `SEPOLIA_RPC_URL`, `RELAYER_PRIVATE_KEY`,
`DEPLOYER_PRIVATE_KEY`, `REGISTRY_ADDRESS`, `ETHERSCAN_API_KEY`. Full list with comments: [`.env.example`](.env.example).

On-chain writes are off under compose. To enable "Register on-chain", add `CHAIN_SEPOLIA_RPC_URL` and
`CHAIN_RELAYER_PRIVATE_KEY` to `.env` (each registration sends a real Sepolia transaction from the relayer).

Demo data and the full demo:

```bash
cd backend && DATABASE_URL=postgresql+asyncpg://cybermatrix:cybermatrix@localhost:5432/cybermatrix uv run python -m demo.seed
scripts/demo.sh             # fresh database → recorded fixtures → the brief's test cases live (~70 s)
```

Verify a report yourself (no backend needed):

```bash
uv run verify/verify.py --report backend/tests/fixtures/sample_report.json \
  --rpc https://ethereum-sepolia-rpc.publicnode.com \
  --address 0x5De4Cd6F651A4D80ddA16fc70431dd669621BeeA \
  --relayer 0x1B7c212ffC6FA799fE6131462F2C05046B8a848e
```

It prints `MATCH` with the on-chain status, time and Etherscan link (exit 0). Change one character in the JSON and
it prints `MISMATCH` (exit 1). Without `uv`: `pip install -r verify/requirements.txt && python verify/verify.py …`.

Tests:

```bash
cd backend && uv run pytest -q && uv run ruff check app tests demo
cd contracts && forge test -vv
cd frontend && npm run typecheck && npm run lint && npm run build
```

Hosting: [`render.yaml`](render.yaml) deploys Postgres, the API and the web app on Render's free tier.

Also included: a browser extension (`extension/`, right-click a link to check it), an organisation dashboard
(`/org`), Certificate Transparency watch (`/watch`) and a STIX 2.1 / plain-text threat feed (`/feeds/*`).

## Disclosures (libraries, templates, AI tools)

- **Built during the round:** all commits are dated 8–10 November 2026 (first commit `2482dc3`, 2026-11-08).
- **Libraries:** all open-source packages listed in `backend/pyproject.toml`, `frontend/package.json` and
  `contracts/lib/forge-std`, used under their licences. Notable: httpx-secure (0BSD), dnstwist, sslyze, web3.py,
  rfc8785, Next.js, Tailwind CSS, Foundry forge-std.
- **Templates:** the frontend started from `create-next-app`. No UI kit or paid template.
- **Public APIs:** Google Safe Browsing, URLhaus, OpenPhish feed, VirusTotal, Cert Spotter, crt.sh, RDAP (IANA
  bootstrap), Google DNS-over-HTTPS, osv.dev, Etherscan, a Sepolia RPC provider, Gemini / Anthropic.
- **Data:** Tranco top sites list (allowlist), Unicode UTS #39 confusables, endoflife.date (end-of-life software
  versions), the ScamShield-IN dataset (Hugging Face, openrail) for evaluation, and the real *public* eMudhra
  intermediate certificates as test fixtures. Nothing is signed with any real CA key.
- **AI coding assistant:** the code and docs were written with the help of Claude Code (Anthropic). At runtime the
  app calls Gemini (Google) or Claude (Anthropic) only for explanations and wording signals, as described above. No
  models were trained.
- **Secrets:** none in the repository; configuration comes from environment variables (see `.env.example`). Git
  history was scanned with gitleaks; the only hits are the public Anvil test keys used by local chain tests.

## Track

HackMatrix: **AI-Powered Web Threat Detection & Digital Trust Intelligence**.

## Licence

MIT, see [LICENSE](LICENSE).
