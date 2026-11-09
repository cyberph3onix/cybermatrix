# CyberMatrix audit (2026-11-09, 21:20–21:53 IST)

Audit only. Nothing was edited, fixed or committed. This file is the only one created.

**Audited code:** `origin/main` = `backend` branch = `015358b` (checked out, clean, in the `../cybermatrix-backend`
worktree), plus the docker compose stack already running from that worktree (backend image built 21:40, after `015358b`).
Line references point to `015358b`.

## 1. Verdict

`origin/main` (`015358b`) contains a working end-to-end system. URL, message, email and QR assessment runs live,
with GSB v5, VirusTotal, URLhaus, OpenPhish, RDAP, CT, TLS and OCSP all completing. The rule-based classification,
the dashboard, Sepolia registration (2 real reports on a source-verified contract) and independent verification
(MATCH, and MISMATCH on a one-character edit, both in verify.py and in the browser) all work. All suites pass:
492 backend, 10 live, 61 Foundry, 9 verify, plus frontend typecheck, lint and build.

Two things threaten the demo:

1. **The AI layer is down in the running stack.** The committed `llm.py` calls only `gemini-2.5-flash-lite`, which
   returns 429 (quota). None of the 22 stored reports has an AI explanation, and message LLM signals are `unavailable`.
   Another session was fixing this in the worktree while I audited (model fallback plus per-model `thinkingConfig`).
   That fix is uncommitted and not deployed.
2. **Your local `main` checkout is stale and dirty.** It is 14 commits behind `origin/main`. Its 26 uncommitted files
   hold a separate security patch (relayer/reporter check in verify.py and `/verify`, one-time disputes) that exists
   nowhere else, and it does not apply cleanly to `015358b`.

**Estimate: about 90% of the mandatory MVP.** Every item works live except AI explanations, which are coded and
tested but return nothing today.

## 0. Branches and worktrees

| Branch | Commit | Last commit | Notes |
|---|---|---|---|
| `origin/main`, `origin/backend`, `backend` | `015358b` | 2026-11-09 21:39 "docs: security methodology overview, current test count" | Newest code. Worktree `../cybermatrix-backend`. Uncommitted edits appeared there during the audit (21:44–21:46): `llm.py`, `eval/scamshield.py`, `test_llm_providers.py`, CLAUDE.md, TESTING.md. **Another session is active in it.** |
| local `main` | `be54482` | 2026-11-09 17:02 "Test UI register, Anthropic fallback and phone widths; fix what they found" | 14 commits behind `origin/main`, plus 26 modified files and the untracked `backend/tests/test_security_review.py`. Not pulled. |
| `contracts`, `frontend` | `97e49df` | 2026-11-09 12:13 "Add .env.example; make frontend typecheck generate its mock fixture first" | Old. Fully contained in main (0 commits not in main). |

The 14 commits after local `main` are: testing report, registry v2 (bonded disputes and revisions), `domain.dns`,
`POSTURE.OUTDATED_SOFTWARE`, ownership proof, DMARC/SPF/DKIM, message campaigns, registry status sync, CT-based
hosting-platform age, GSB `hashes.search`, browser extension, CT watchlist, and docs.

## 2. Commands run

| Command | Result |
|---|---|
| `cd backend && uv run pytest -q` | **492 passed, 10 deselected (live), 0 failed**, 8.8 s |
| `uv run pytest -q -m live` | **10 passed**, 30.5 s (badssl.com, crt.sh). Threat intel and Gemini have no automated live test; I exercised them through `/assess` instead (below). |
| `forge build && forge test -vv` | **61 passed, 0 failed** (including 3 fuzz tests × 1000 runs). Lint notes only (unsafe-typecast). |
| verify tests (`verify/tests`) | **9 passed** |
| `verify.py --report sample_report.json` (live Sepolia, v2 `0x4650…BbB4`) | **MATCH**. Computed hash = `0xe8db935c3a232b5389c14869c1d0ace58d0f38c6231d1ecff0fecdceb2ad91d3`, as expected. id 1, `validated`, reporter = relayer, tx `0x9e5e9b57…06c2`. Exit 0. |
| same, with one character changed (`schema_version`) | **MISMATCH**, "hash is not registered in this contract" |
| `npm run typecheck` / `npm run lint` / `npm run build` | exit 0 / 0 / 0. Routes: `/`, `/clusters`, `/report/[id]`, `/verify`, `/watch` |
| `docker compose config` | valid |
| `docker compose up --build` | **Not run.** The stack from the worktree was already up and another session is using it, so I tested against it instead. |
| `POST /assess https://www.sbi.co.in` | `low_risk`, R5, score 0, **coverage 100%**, confidence high. Redirects `www.sbi.co.in` 301 → `sbi.co.in/redirect/`. Posture: NO_XFO, NO_XCTO (0 points). |
| `POST /assess https://testsafebrowsing.appspot.com/s/phishing.html` (Google's test phishing page) | **`confirmed_malicious`**, R1: URL.INTEL.GSB + URL.INTEL.VT_MAJORITY, 100% coverage, but `page.llm unavailable: gemini: HTTPStatusError` |
| `POST /assess http://paypal.com.secure-login-verify.top/signin` (made-up name) | `suspicious`, R3: URL.BRAND_IN_SUBDOMAIN + TLS.NO_HTTPS, 65% coverage (DNS fails, so fetch/RDAP are unavailable and listed in limitations) |
| Scam SMS (SBI KYC + GSB test link + OTP + phone + UPI) | `confirmed_malicious` via its link (R1). Indicators: url, domain, phone, upi_id, brand_claimed, message_family. Stored subject is redacted (`[PHONE]`, `[UPI]`). `message.signals unavailable` (Gemini). |
| Urgency-only message | `inconclusive` (R4, coverage 40% because the LLM is down), score 3. Did not exceed suspicious. |
| `POST /assess sbi.co.in` / `alerts@paypa1-secure-login.xyz` | `low_risk` 100% / email → `suspicious` (TYPOSQUAT + CORR.PRIOR_REPORTS) |
| SSRF via live API: `http://169.254.169.254/latest/meta-data/`, `http://0x7f000001:8000/health` | Fetch blocked: "address 169.254.169.254 is not a public address", "port 8000 not allowed" |
| `GET /clusters` | 3 clusters (shared domain and shared `cert_sha256`). Two have Gemini-written summaries from earlier today, labelled with `summary_model`. |
| `GET /trends/impersonation`, `GET /reports/{id}/history` | PayPal: 5 reports. History lists v1 with its tx. |
| `GET /reports/9edd…f036/verify` (registered from the backend, on-chain id 2) | `match: true`, status `submitted`, tx `0xfa8c911c…3119` |
| Gemini probe | `gemini-2.5-flash-lite` → 429 RESOURCE_EXHAUSTED. `gemini-3.5-flash-lite` and `flash-lite-latest` → 200 for a plain call but **400 INVALID_ARGUMENT when sent `thinkingConfig.thinkingBudget=0`**, which the committed `llm.py` always sends. Calling the committed `explain()` with `GEMINI_MODEL=gemini-3.5-flash-lite` therefore fails too. |
| Sepolia | v2 `0x465094577Fe42BD31d705581bD3baAB51397BbB4` (4809 bytes of code). Etherscan API: **source verified**, `ThreatRegistry`, v0.8.24. `getReport`: 2 reports, both from relayer `0x1B7c…848e`. Deploy tx `0x6585a3d9…0d09`. v1 `0x22Cc…73bc` retired. |
| Browser (Chrome, real backend) | `/report/{id}` renders live data. `/verify` by ID → MATCH. `/verify` file upload: untouched → MATCH, one character changed → MISMATCH (hashed in the browser). At 360 px (iframe): no horizontal overflow on `/`, two report pages, `/verify` or `/clusters`. |

## 3. Checklist

### M1 URL and website analysis

| Item | Status | Evidence | Gap |
|---|---|---|---|
| Normalise/inspect URL | DONE | live `/assess`; `normalized_subject`; `tests/test_urlutil.py` | |
| Domain structure, naming | DONE | DOMAIN.SUSPICIOUS_TLD, URL.KEYWORDS live | |
| Typosquat / homoglyph / brand-in-subdomain | DONE | live TYPOSQUAT (email case), BRAND_IN_SUBDOMAIN; `tests/test_url_checks.py` | |
| Userinfo trick, embedded redirect param | DONE (tests) | `tests/test_url_checks.py` passes; not exercised live | |
| Redirect chain + destinations | DONE | live sbi hops; safe_fetch `MAX_HOPS=5` `app/fetch/safe_fetch.py:30` | |
| TI: GSB v5 | DONE | live R1 hit on Google's test page | |
| TI: VirusTotal | DONE | live VT_MAJORITY / VT_MINORITY | |
| TI: URLhaus, OpenPhish | DONE (ran) | `completed` in live coverage; no positive hit seen live (unit tests cover hits) | No live positive case |
| DNS / RDAP age | DONE | `domain.rdap` and `domain.dns` completed live | |
| Association with known reports | DONE | CORR.PRIOR_REPORTS live (email case) | |
| Output contents | DONE | report has subject, findings and evidence with source, intel, redirects, class, `recommended_actions`, limitations | |

### M2 TLS and web trust

| Item | Status | Evidence | Gap |
|---|---|---|---|
| Validity / expiry / SAN / issuer / chain | DONE | live `certificate` block (chain_valid, san, days_remaining, chain_issuers) | |
| Revocation (OCSP) | DONE | live `ocsp_status: good` | CRL not exercised live |
| Key size, signature algorithm | DONE | `key_type`/`key_bits`/`signature_algorithm` live; TLS.WEAK_* tests | |
| CT (Cert Spotter → crt.sh) | DONE | `tls.ct` completed live; 10 live tests | |
| eMudhra distrust (cert AND SPKI) | DONE | `distrusted_cas.json`: 17 entries, **17/17 with `spki_sha256` and `cert_sha256`**; cross-signs share the SPKI; `test_demo_seed` asserts esign-verify.in → R1 TLS.DISTRUSTED_CA | Demo only (no live site exists, by design) |
| Certificate verdict: valid / suspicious / potentially compromised | **PARTIAL** | Cert fields are shown in `frontend/components/CertificateCard.tsx` | No explicit three-way verdict label in the schema or UI. Judges must infer it from the findings. |
| tls_config vs tls_trust split | DONE | categories in RISK_ENGINE §6; posture split | |
| Valid cert ≠ legitimacy | DONE | `CertificateCard.tsx:34` "A valid certificate does not mean the site is legitimate" | |

### M3 AI scam and message analysis

| Item | Status | Evidence | Gap |
|---|---|---|---|
| Social-engineering, urgency, payment, impersonation (regex) | DONE | live MSG.CREDENTIAL_REQUEST, PAYMENT_REQUEST, URGENCY, AUTHORITY_IMPERSONATION, SCAM_PATTERN | |
| LLM language signals | **UNVERIFIED (broken live)** | `message.signals unavailable: gemini: HTTPStatusError` on every live message | Gemini quota / `thinkingConfig` (see §4) |
| Extract URLs, emails, phones, UPI | DONE | live indicators incl. phone and upi_id | |
| Extracted URLs through `assess_url` | DONE | `app/pipeline_message.py:71`; live R1 came from the link | |
| Plain-language explanation | **PARTIAL** | `app/ai/explain.py` plus mocked tests pass; **0/22 stored reports have `ai`** | Not working live |
| Safety recommendations | DONE | `recommended_actions` live (1930 helpline, cybercrime.gov.in) | |
| Language ≤ suspicious | DONE | `tests/test_risk.py:63 test_heuristics_alone_never_exceed_suspicious`, `HEURISTIC_CAP=30` `app/engine/risk.py:11`; live urgency-only → inconclusive | |

### M4 Threat correlation

| Item | Status | Evidence | Gap |
|---|---|---|---|
| Repeated domain / cert infra | DONE | live clusters on domain and `cert_sha256` | IP/ASN/NS only in tests |
| Similar messages | DONE (tests) | `message_family` indicator live; `4d8609d` campaigns | |
| Recurring impersonation | DONE | live `/trends/impersonation` | |
| Prior reports / clusters | DONE | live CORR.PRIOR_REPORTS, `/clusters` | |
| Deterministic joins, LLM only summarises | DONE | clusters built from indicator joins; `summary`/`summary_model` labelled | |

### M5 Website security assessment

| Item | Status | Evidence | Gap |
|---|---|---|---|
| Headers (HSTS/CSP/XFO/XCTO) | DONE | live POSTURE.* on sbi and appspot | |
| Insecure HTTP | DONE | TLS.NO_HTTPS live | |
| Weak TLS config, old TLS version, version banners, EOL software | DONE (tests) | `tests/test_rdap_headers.py`, `afa652a` | Not seen live |
| Mixed content | DONE (tests) | POSTURE.MIXED_CONTENT in catalogue (66/66 spec IDs present in code) | |
| Exposed-file probe gated on ownership | DONE | ownership proof (`/ownership/challenge`/`verify`, `27e64a7`); `test_owns_site_without_proof_is_refused_and_rate_limited` | |
| Finding fields (issue, evidence, impact, severity, remediation, limitations) | DONE | live POSTURE.NO_HSTS has title, evidence, impact, severity, recommendation, limitation | |
| Not in the phishing score | DONE | sbi: two posture findings, score 0, `low_risk` | |

### M6 Decentralised threat intelligence

| Item | Status | Evidence | Gap |
|---|---|---|---|
| Submit report hash on-chain | DONE | 2 real reports; backend tx `0xfa8c…3119` | |
| Verifiable history / revisions (parent → Superseded) | DONE | `/reports/{id}/history` live; Foundry supersede tests | Live revision tx not observed |
| Disputes (bonded) / validation status | DONE | report 1 `validated` (validate tx in `deployments/sepolia.json`); 61 Foundry tests | No live dispute tx observed |
| Independent verify.py (no backend imports) | DONE | imports only stdlib, rfc8785, eth_hash, web3; live MATCH/MISMATCH | |
| Provenance (reporter address) | **PARTIAL** | reporter shown | **MATCH does not check the reporter.** `verify/verify.py:155`, `app/api/routes.py:449` (`match=onchain is not None`). Anyone can register the hash of a forged report.json from any address and get MATCH. The fix exists only in your local uncommitted patch. |
| Nothing sensitive on-chain | DONE | `submitReport(reportHash, parentHash)` only (`app/registry/chain.py:214`); salted report (`schemas.py:189`); dispute reasons stored off-chain as a hash | |

### Report contents (§6)

| Item | Status | Evidence |
|---|---|---|
| 5 classes | DONE | low_risk, suspicious, confirmed_malicious, inconclusive seen live; high_risk in `tests/test_risk.py` |
| Indicators, evidence, source per finding, timestamp, coverage + confidence, actions, limitations | DONE | live reports; `Evidence.source` required; `Finding.evidence` `min_length=1` |
| Never "safe" | DONE | grep: no user-facing "safe" in frontend or API strings (only "Google Safe Browsing" and comments); R5 text is "No significant malicious indicators within the checks performed." |

### Mandatory MVP (§7)

| Item | Status |
|---|---|
| URL analysis, phishing detection, TLS analysis, scam detection, risk assessment | DONE |
| ≥1 external TI source | DONE (4 complete live; GSB and VT hit) |
| AI explanations | **PARTIAL: broken live today** |
| On-chain registry, independent verification | DONE |
| Functional dashboard | DONE (real backend, not mocks) |
| Testing ≥3 suspicious + ≥3 benign, documented | DONE: `docs/TESTING.md` (4 bad, 4 benign, ScamShield-IN 528 held-out) |

### UX walk (§5), against the REAL backend

| Step | Status | Notes |
|---|---|---|
| 1 Submit URL / domain / email / message / QR from `/` | DONE (API); UI form present | Auto-detect live: URL, email and message correct. A bare domain `sbi.co.in` is stored as `subject_type: url` although `detect.py:22` returns DOMAIN (cosmetic). QR upload not exercised live. |
| 2 Investigate live | DONE | RDAP, TLS, CT, OCSP and 4 TI sources completed live |
| 3 Deterministic + AI on the report page | **PARTIAL** | Deterministic yes. The AI box is empty: the page says "AI explanation not generated". |
| 4 Threats, evidence, sources, precautions, limitations | DONE | browser page text confirms |
| 5 Register + verify | DONE (verify); register seen via tx | `/verify` MATCH and tamper MISMATCH confirmed in the browser. I did not press "Register on-chain" (it sends a real tx); the backend-registered report proves the path works. |
| Phone width | DONE at 360 px (iframe) | Not on a physical device |

### Security and privacy (§9)

| Item | Status | Evidence |
|---|---|---|
| SSRF (private, loopback, link-local, CGNAT, metadata, IPv6, IPv4-mapped, decimal/octal/hex) | DONE | `tests/test_safe_fetch.py` parametrised list (`2130706433`, `0177.0.0.1`, `0x7f000001`, `::ffff:7f00:1`, metadata.google.internal); live metadata block |
| Redirect re-validation per hop, DNS-rebinding pinning | DONE (tests) | `safe_fetch.py:157` `_connect_policy` on the connected IP; `test_public_redirect_to_private_is_blocked` |
| Caps: 5 s, 2 MB, text only, decompressed cap | DONE | `safe_fetch.py:30-35,213` |
| No JS, no binaries, no port scans | DONE | ports 80/443/8080/8443 enforced live |
| Per-IP rate limit | DONE | `tests/test_api.py:161`; `routes.py:83` |
| Raw HTTP to user targets outside safe_fetch | None found | sslyze connects to the safe_fetch-validated IP (`tls_chain.py:95`); `llm.py` httpx goes to a fixed Gemini host |
| httpx-secure pinned | DONE | `==2.0.0` in pyproject and uv.lock |
| `<untrusted_input>`, schema validation, unknown check_ids dropped, forced heuristic | DONE | `message_signals.py:40-53`, `explain.py:44-51`; `test_llm_unknown_ids_dropped_and_strength_forced_heuristic` |
| LLM never sets the class | DONE | `risk.classify(findings, coverage)` `risk.py:99`; `_explain` runs after the pipeline `routes.py:119`; `test_hostile_llm_output_cannot_change_classification_or_inject_findings` |
| Prompt-injection test | DONE | `test_message.py:96 test_injection_cannot_change_verdict_or_say_safe` |
| Redaction before external calls | DONE | `pipeline_message.py:42` redacts before the LLM at `:57`; the live limitations line lists what was masked. Extracted URLs still go to GSB (hash prefix) and VT (full URL), by design. |
| No floats; salt present | DONE | 0 floats across 5 live reports; `schemas.py:189` |
| .env never committed | DONE | `git log --all -- .env` empty; only `.env.example` tracked |
| No private keys in repo; eMudhra keys never used | DONE | no `PRIVATE KEY` blocks in tracked files; `tests/certgen.py` generates fresh keys; demo uses the public eMudhra cert only |
| Keys not logged | DONE | Gemini key sent in a header; `LlmUnavailable` strips request details |

### Scope (§13)

No violations found. Built beyond the brief: browser extension, CT watchlist, bonded disputes and v2 redeploy,
DNS-over-HTTPS, ownership proof, DMARC parsing. All of it landed (18:43–19:14) after the MVP was working. The cost
is that the AI regression (quota) went unnoticed while those features were added.

### Deliverables (§10)

| Deliverable | Status |
|---|---|
| Working prototype | DONE (AI excepted) |
| Public GitHub repo + setup | DONE: `github.com/cyberph3onix/cybermatrix` is PUBLIC; README has compose and verify instructions |
| AI demo | **PARTIAL** (broken live) |
| Cybersecurity demo incl. TLS | DONE (live, plus the eMudhra demo seed) |
| Testnet contract + address + tx | DONE (README, `contracts/deployments/sepolia.json`) |
| Technical docs | DONE: ARCHITECTURE, RISK_ENGINE, DECISIONS, TESTING |
| Testing report | DONE |
| Live end-to-end demo path | PARTIAL until AI is restored |

## 4. Rule violations (most severe first)

1. **Provenance gap (Web3, medium).** `verify.py` and `/verify` say MATCH for any registered hash, whoever registered
   it (`verify/verify.py:155`, `routes.py:449`), so a forged report can be "verified". A fix exists only in your local,
   uncommitted, non-applying patch on `be54482`.
2. **AI down (breaks the AI demo, not a safety rule).** `gemini-2.5-flash-lite` returns 429, and newer models return
   400 because `thinkingBudget` is sent to every model. Fail-safe works: the verdict is rule-based and the limitation
   is shown. In-progress, uncommitted fix in the worktree.
3. **Unmerged local work at risk (process).** 26 modified files on local `main` conflict with `origin/main`.
4. **Minor.** Raw phone and UPI values sit in report JSON served by `GET /reports/{id}` to anyone holding the UUID
   (rule 7 is met because they stay off-chain). URLs that look internal are still looked up on VirusTotal. No CLAUDE.md
   non-negotiable is breached.

## 5. Top 10 remaining work (priority, hours)

1. Restore live AI: commit and deploy the other session's model fallback with per-model `thinkingConfig`, add an
   `ANTHROPIC_API_KEY` as a second fallback, and add a live smoke test. **1 h** (AI 20)
2. Reconcile local `main`: rebase the reporter-trust check onto v2 (verify.py `--relayer`, `/verify` reporter check,
   UI warning) and check whether `_disputeResolved` still makes sense next to bonded re-disputes. **1.5 h** (Web3 20, Cyber 30)
3. Rebuild the stack and rehearse the full flow live: scam SMS → explanation → register → `/verify` → tamper. **1 h**
4. Add a certificate verdict (valid / suspicious / potentially compromised) to the card, derived from the TLS findings. **1 h** (Cyber)
5. Do one live revision and one bonded dispute on Sepolia, and record the tx hashes in README/TESTING. **0.5 h** (Web3)
6. Add a live positive case for URLhaus/OpenPhish (from the current feed, at demo time) to TESTING. **0.5 h**
7. Keep `subject_type: domain` for bare domains (detect vs pipeline mismatch). **0.3 h**
8. Replace raw labels in the UI ("posture.headers", "4 not applicable") with readable names. **0.5 h** (UX 10)
9. Mask phone/UPI values in the public report view (keep them in the DB). **1 h** (privacy)
10. Phone check on a physical device, and a recorded fallback video in case the network fails. **1 h**

## 6. Not checked, and why

- `docker compose up --build`: not rerun, because another session is using the running stack.
- "Register on-chain" button: not pressed (it sends a real Sepolia tx and writes the DB). Proven by the existing
  backend-registered report.
- QR upload, UPI QR, `/watch`, the browser extension and MetaMask disputes: not exercised.
- Live URLhaus/OpenPhish hits, IP/ASN/NS correlation, mixed content and weak-TLS posture: unit tests only.
- The other session's uncommitted edits: they changed during the audit and were not tested.
- Physical phone.
