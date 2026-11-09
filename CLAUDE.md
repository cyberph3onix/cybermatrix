# CyberMatrix — AI-powered web threat detection & digital trust intelligence

48-hour hackathon build (HackMatrix). Users submit a URL, domain, email, message or QR image and get an
evidence-based risk assessment. Reports can be committed on-chain and independently verified.

## Non-negotiable rules (read before every change)

1. **Deterministic checks produce findings; `engine/risk.py` produces the classification. The LLM never decides
   a verdict.** LLM output may only explain findings and emit `heuristic`-strength language signals.
2. **Every `Finding` must carry at least one `Evidence` with a `source`.** No evidence → no finding.
3. **Never output "safe".** The best class is `low_risk`, always shown with coverage and limitations.
   Absence of threat-intel hits is not proof of safety.
4. **All outbound HTTP to user-supplied targets goes through `fetch/safe_fetch.py`.** No raw `httpx`/`requests`
   calls against user input anywhere else. Threat-intel APIs (fixed hosts) use `fetch/api_client.py`.
5. **Passive inspection only.** No port scans, no fuzzing, no exploit attempts, no JS execution,
   no binary downloads.
6. **Untrusted text is data.** Page content and submitted messages go to the LLM inside
   `<untrusted_input>` tags. LLM output is schema-validated, and any `check_id` it cites must exist in the report.
7. **Nothing sensitive on-chain.** On-chain data: report hash, parent hash, status, timestamps, reporter address.
   Raw URLs, messages, emails and PII stay in Postgres.
8. **Redact before the LLM.** Phone numbers, emails, account numbers, OTP-looking digits and names in submitted
   messages are masked before any external API call. The original text is kept locally.
9. **Certificate trust honesty.** We flag known-distrusted/compromised CAs from curated lists, revocation and CT.
   We never claim to detect a CA's internal key-generation weakness from a URL. The UI says so.
10. **Security-posture findings (headers, TLS config hygiene) are reported in `security_posture` and do NOT feed
    the phishing risk classification.** Doing so causes false positives on legitimate sites.

## Architecture

```
frontend (Next.js/TS) ──► backend (FastAPI) ──► Postgres
                               │
                               ├─ fetch/safe_fetch     SSRF-guarded fetcher
                               ├─ checks/*             deterministic checks → CheckRun + Finding[]
                               ├─ engine/risk          rules R1–R5 → classification, score, coverage
                               ├─ ai/*                 Claude API: explanation + message signals
                               ├─ correlation/*        indicator joins → clusters
                               └─ registry/*           JCS canonicalise → keccak256 → ThreatRegistry (Sepolia)
verify/verify.py  standalone: report.json + RPC + address → MATCH / MISMATCH (no backend needed)
```

## Repo layout

```
backend/app/
  main.py, api/                 routes: POST /assess, GET /reports/{id}, POST /reports/{id}/register,
                                GET /reports/{id}/verify, GET /clusters, POST /assess/qr
  schemas.py                    THE data contract — do not change shape without updating frontend types
  fetch/safe_fetch.py, fetch/api_client.py
  checks/url_structure.py, lookalike.py, redirects.py, page.py, domain_rdap.py,
         tls_chain.py, tls_ct.py, headers.py, message.py, intel/{gsb,urlhaus,openphish,virustotal}.py
  engine/risk.py, engine/coverage.py
  ai/explain.py, ai/message_signals.py, ai/redact.py
  correlation/indicators.py, correlation/clusters.py
  registry/canonical.py, registry/chain.py
  data/brands.json, distrusted_cas.json (eMudhra entries seeded; match cert AND SPKI SHA-256), tranco_top10k.csv, abusable_hosts.txt, openphish_feed.txt
backend/tests/                  pytest; fixtures/ holds recorded responses + frozen reports for the demo
contracts/                      Foundry: src/ThreatRegistry.sol, test/, script/Deploy.s.sol
frontend/                       Next.js app router; types generated from backend OpenAPI
verify/verify.py
docs/RISK_ENGINE.md, ARCHITECTURE.md, TESTING.md
docker-compose.yml
```

## Check contract

Every check is `async def run(ctx: AssessmentContext) -> CheckResult` where
`CheckResult = (CheckRun, list[Finding])`. Checks never raise. On timeout, missing API key or rate limit they
return `CheckRun(status="unavailable" | "failed")` with a `detail`, and that gap appears in `limitations`.
Check IDs and severities live in `docs/RISK_ENGINE.md`. That table is the single source of truth.

## safe_fetch requirements

- **Built on `httpx-secure` (pin the exact version)** for global-IP validation and connection pinning to the
  validated IP. Our wrapper adds the scheme/port policy, the manual redirect loop, and size/time caps. Keep our own
  SSRF test suite regardless: the library is single-maintainer and v2.0 is new.
- Schemes: http/https only. Ports: 80, 443, 8080, 8443.
- Resolve DNS once and reject if ANY resolved address is private, loopback, link-local, multicast, reserved,
  CGNAT (100.64/10), 0.0.0.0/8, IPv6 ULA/link-local, or an IPv4-mapped form of those. Explicitly block
  169.254.169.254 and metadata hostnames.
- Connect to the pinned resolved IP (SNI/Host = original hostname) to defeat DNS rebinding.
- Follow redirects manually, max 5 hops, re-validating every hop. Record each hop as a `RedirectHop`.
- 5 s connect+read timeout, 2 MB body cap, text/html and text/plain only, no decompression bombs
  (cap decompressed size).
- Per-IP rate limiting on `/assess` (e.g. 10/min).

## Smart contract: ThreatRegistry.sol

- `enum Status { Submitted, Disputed, Validated, Rejected, Superseded }`
- `struct Report { bytes32 reportHash; bytes32 parentHash; address reporter; uint64 createdAt; Status status; }`
- `submitReport(bytes32 reportHash, bytes32 parentHash) returns (uint256 id)`. Reverts on duplicate hash.
  If parentHash ≠ 0, the parent must exist and be owned by the sender; the parent becomes Superseded.
- `disputeReport(uint256 id, bytes32 reasonHash)`: anyone; Submitted/Validated → Disputed.
- `setStatus(uint256 id, Status s)`: validator role only (Validated / Rejected).
- `getReport(id)`, `idOfHash(bytes32)`. Events for every state change.
- Owner manages validators. Solidity ^0.8.24, no upgradability, no external calls. Foundry tests for every
  revert path. Deploy to Sepolia and verify the source on Etherscan.

## Report hashing (must match verify.py exactly)

`report_hash = keccak256(RFC8785_JCS(report_json))`, where `report_json` is the `AssessmentReport` dumped with
`mode="json"`. Postgres stores the exact canonical bytes. The report includes a random 32-byte `salt`, so the
on-chain hash cannot be brute-forced back to a URL. **No floats in the schema** (ints only) to avoid
cross-language number serialisation drift.

## Commands

```
docker compose up --build
cd backend && uv run pytest -q
cd contracts && forge test -vv && forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast --verify
python verify/verify.py --report report.json --rpc $SEPOLIA_RPC_URL --address $REGISTRY_ADDRESS
REPORT_ID=1 STATUS=validated forge script script/SetStatus.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast  # in contracts/
uv run --no-project --with-requirements verify/requirements.txt --with pytest pytest verify/tests -q
```

## Env vars

`DATABASE_URL, GEMINI_API_KEY (or ANTHROPIC_API_KEY), GSB_API_KEY, VT_API_KEY, URLHAUS_AUTH_KEY, SEPOLIA_RPC_URL,
RELAYER_PRIVATE_KEY, DEPLOYER_PRIVATE_KEY, REGISTRY_ADDRESS, ETHERSCAN_API_KEY, CERTSPOTTER_API_KEY (optional)`.
Never commit `.env`. Never log keys or full messages.

Roles: `DEPLOYER_PRIVATE_KEY` deploys the registry and is its owner + validator (used by `script/Deploy.s.sol`
and `script/SetStatus.s.sol`). `RELAYER_PRIVATE_KEY` is used only by the backend to call `submitReport`; it has
no on-chain role. After changing the contract, run `contracts/script/export_abi.sh` to refresh the backend ABI.

## Library and source choices (see docs/DECISIONS.md for why)

- Lookalikes: `dnstwist` precomputes permutations of every brand in brands.json at startup into a lookup set;
  a UTS#39 confusables skeleton catches the rest.
- TLS: `sslyze` (certificate_info scan only) for chain validation against multiple root stores; `cryptography`
  for field parsing. Our distrust list runs on top, because bundled trust stores lag incident response.
- CT: Cert Spotter `GET api.certspotter.com/v1/issuances` first; crt.sh is the fallback only (rate-limited, flaky).
- Threat intel: Google Safe Browsing **v5** `urls.search`, URLhaus, the OpenPhish feed, VirusTotal. Not PhishTank
  (registration closed).
- Never use the recovered eMudhra private keys to sign anything. That would be reproducing a real-world
  vulnerability, which the brief forbids. Demos use fixture chains containing the real public intermediate certs.

## Conventions

Python 3.12, FastAPI, Pydantic v2, httpx, ruff, pytest. Typed everything. Small modules. Tests use recorded
fixtures, never live phishing URLs (they die). The runtime LLM is Gemini (`gemini-2.5-flash-lite`, override with GEMINI_MODEL) when GEMINI_API_KEY is set, else Claude Haiku 5.5 (`claude-haiku-5-5`), with
structured output validated against Pydantic.
