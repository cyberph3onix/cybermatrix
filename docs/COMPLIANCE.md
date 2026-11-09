# Compliance matrix: HackMatrix brief vs CyberMatrix

Audit run 2026-11-10. Requirement text: `docs/PROBLEM_STATEMENT_CHECKLIST.md`. Every "evidence" entry was produced or
read in this audit session. Test names are under `backend/tests/` unless stated. "Fix" lists the audit commit.

**Verdict: GO for deliverable prep**, with three open items that need a decision from you (D-2 licence and README,
D-5 dispute tx). Nothing in Phase 0 failed.

## Phase 0: does it run

| # | Check | Result | Evidence |
|---|---|---|---|
| 0.1 | Clean clone, fresh volumes, `docker compose up --build` | PASS | Clone in scratchpad, compose project `cmclean` (`down -v` first), at `ad9bf80` with no `.env` and again at `32bf54b` with `.env`: postgres healthy, backend healthy, `/health` ok, frontend 200. A stale stack from the `../cybermatrix-backend` worktree was crash-looping (its postgres had exited); I stopped it (`docker compose stop`, volumes kept) to free the ports |
| 0.2 | Backend tests + ruff, Foundry, frontend | PASS | `uv run pytest -q`: 537 passed at start, **656 passed** at end; ruff clean; `pytest -m live` 10 passed; `forge test` 70 passed; `npm run typecheck`, `lint`, `build` exit 0; verify tests 13 passed |
| 0.3 | verify.py on the sample fixture | PASS | `docs/evidence/verify_match.txt`: MATCH, hash `0xe8db935c…ad91d3`, exit 0. One-char edit (`schema_version` 1.0.0→1.0.1): MISMATCH, exit 1 (`verify_mismatch.txt`). Re-run after the schema change in `00602e4`: still MATCH |
| 0.4 | Sepolia deployment + source verification | PASS | `docs/evidence/onchain.md`: v3 `0x5De4Cd6F651A4D80ddA16fc70431dd669621BeeA`, Etherscan `getsourcecode` returns ThreatRegistry v0.8.24; deploy tx `0xbdf33b29…b3b`, submitReport `0x08d6c9ef…7c5`, setStatus `0xab1eef21…6c0`, all status 1 |
| 0.5 | Each intel check with the real `.env` | PASS, none unavailable | GSB test URL: `intel.gsb`, `intel.urlhaus`, `intel.openphish`, `intel.virustotal`, `page.llm` all `completed`, coverage 100%, `confirmed_malicious` R1 (GSB + VT_MAJORITY) |
| 0.6 | Secret scan of full history | PASS (no real secret) | gitleaks 8.21.2 over 42 commits, all refs: 7 hits, all the public Anvil dev keys in `test_chain.py` / `test_verify.py` (`docs/evidence/gitleaks.json`, redacted). Every value in the real `.env` grep'd against `git log --all -p`: 0 occurrences for every key. Nothing to rotate |

## Phase 1: requirement matrix

### Input and UX

| ID | Status | Evidence | Fix |
|---|---|---|---|
| IN-1 | DONE | `docs/evidence/e2e_inputs.json` (clean stack, real keys): URL → confirmed_malicious; bare domain `WWW.SBI.CO.IN.` → low_risk 100%; email address → suspicious (TYPOSQUAT); email with headers → DMARC_FAIL + SENDER_DOMAIN_MISMATCH, confirmed_malicious; message → confirmed_malicious via its link, injection flagged; QR PNG → `qr`, confirmed_malicious. The run found the bare domain detected as a *message*; fixed | `32bf54b` |
| IN-2 | DONE | Browser check (Chrome, clean stack): `/investigate` → report page with "How we investigated" (7 questions, sources, verdict), findings, "Community registry: Register on-chain", Fingerprints; `/verify` page exists. Verify-by-upload covered by `test_api.py::test_verify_uploaded_file_match_and_tamper` | — |
| IN-3 | DONE | Report page text: every finding shows title, severity, strength, check ID, evidence and source; banner gives class + "Why this class: R1: TLS.DISTRUSTED_CA" | — |

### M1 URL and website analysis

| ID | Status | Evidence | Fix |
|---|---|---|---|
| M1-1 | DONE | `test_urlutil.py::test_normalisation` (case, trailing dot, %-encoded host, Cyrillic → punycode, userinfo), `test_parse_backslash_and_userinfo`, `test_ip_literals`. Found: `https://%73bi.co.in/` was analysed as host `%73bi.co.in` while browsers open `sbi.co.in`; hosts are now %-decoded | `5b6d772` |
| M1-2 | DONE | `test_url_checks.py::test_url_checks`, `test_short_brand_neighbours_produce_nothing`, `test_global_brand_lookalikes_…` | — |
| M1-3 | DONE | typosquat/homoglyph/brand-in-subdomain/userinfo/IP/embedded-redirect: `test_url_checks.py`; claimed vs actual identity: PAGE.* in `test_redirects_page.py`; cross-domain redirects + shortener expansion: `test_risk.py::test_redirect_shortener_to_evil_fires`, `…_to_amazon_dampened`; previously reported: `test_correlation.py::test_two_prior_suspicious_reports_raise_prior_reports` | — |
| M1-4 | DONE | `test_safe_fetch.py::test_redirect_chain_recorded_and_cross_domain`, `test_max_hops`; report page "Redirect chain" renders each hop with status and IP | — |
| M1-5 | DONE (4 of 4) | Phase 0.5 live run; offline `test_intel.py` | — |
| M1-6 | PARTIAL | `checks/dns.py` (DoH via dns.google): A, NS, MX, TXT; DOMAIN.FAST_FLUX (≥5 A records, ≥3 /16s, TTL ≤300 s), DOMAIN.FREE_DNS; NS/IP shared with prior reports → CORR.SHARED_INFRA (`test_correlation.py::test_shared_infra_is_low_…`). Tests: `test_dns.py` (7). **Not done:** AAAA is not queried, and a standalone "very low TTL" heuristic was deliberately not added: AWS ELB (60 s) and Cloudflare-proxied (300 s) legitimate sites would trip it. Low TTL counts only inside FAST_FLUX | — |
| M1-7 | DONE | CORR.* tests in `test_correlation.py`; TI matches in every report; `test_audit_correlation.py` | `c50dda0` |
| M1-8 | DONE | Schema: `recommended_actions`, `findings`, `indicators`, `redirect_chain`, `certificate`, `coverage`. Browser: "What to do now", "Redirect chain", "Certificate", and (added) "Indicators" sections all render | `007410a` |
| M1-9 | DONE | brands.json: 8 banks, Paytm/PhonePe/GPay/NPCI/PayPal, WBJEE, IEM, Income Tax/GST/UIDAI/EPFO, India Post, Naukri/LinkedIn, Google/Meta/Microsoft. `test_audit_messages.py::test_each_brief_sector_lookalike_is_flagged` (9 sectors incl. account-recovery) | `5b6d772` |

### M2 TLS and web trust

| ID | Status | Evidence | Fix |
|---|---|---|---|
| M2-1 | DONE | `test_tls_chain.py`: expired, not-yet-valid, self-signed, untrusted root, hostname mismatch/wildcards, weak key, weak signature, incomplete chain, distrust (cert + SPKI), removed root, stapled OCSP revoked, OCSP wrong signer; `test_tls_ct.py`: Cert Spotter, crt.sh fallback, not logged, embedded SCTs; live badssl/crt.sh: `-m live` 10 passed | — |
| M2-2 | DONE | `engine/cert_verdict.py`, `GET /reports/{id}/certificate-verdict`; `test_audit_tls.py::test_certificate_verdict_table` (9 rows). Served as a derived endpoint, not a report field, because `chain.py` re-hashes parsed reports and a new field would change every registered hash | `9df2e75` |
| M2-3 | DONE | Browser: findings grouped "Certificate trust" vs "TLS configuration"; cert card lists "Trust problems: TLS.DISTRUSTED_CA / Configuration problems: TLS.INCOMPLETE_CHAIN" | `9df2e75` |
| M2-4 | DONE | `test_audit_tls.py::test_emudhra_chain_is_confirmed_malicious_and_potentially_compromised`, `test_real_sectigo_cross_sign_is_potentially_compromised_via_spki`; `test_tls_chain.py::test_real_sectigo_cross_sign_matches`. Demo seed on the clean stack: `docs/evidence/emudhra_report.json` (R1: TLS.DISTRUSTED_CA) | — |
| M2-5 | DONE | Cert card footer and report limitations (browser text); DECISIONS.md "What we do NOT claim"; finding limitation asserted in `test_distrusted_intermediate_by_cert_hash` ("key-generation"). Grep of frontend/LLM prompts: no overclaim | — |
| M2-6 | DONE | `CertificateCard.tsx` banner is unconditional; seen on the eMudhra report in the browser | — |
| M2-7 (P2) | DONE | `test_tls_ct.py::test_unexpected_issuer`; `/watch` CT watchlist (`test_watch.py`) | — |

### M3 scam and message analysis

| ID | Status | Evidence | Fix |
|---|---|---|---|
| M3-1 | DONE | MSG.REMOTE_ACCESS_REQUEST (medium) and MSG.INVESTMENT_LURE (low), heuristic, in RISK_ENGINE.md, catalogue, regex and LLM allowlist. `test_audit_messages.py::test_scam_pattern_fixture_fires` (11 fixtures: job+fee, crypto+wallet, prize, refund, bank, university, support, credential, KYC, AnyDesk, .apk). Eval sample still 25/25, 0/30 | `dd67209` |
| M3-2 | DONE | `test_message.py::test_extraction`, `test_message_with_link_runs_url_pipeline_and_attaches_indicator_ref`; correlation of UPI/phone: `test_api.py::test_upi_payee_seen_in_two_…`. Message reports now also carry their links' infrastructure | `c50dda0` |
| M3-3 | DONE | E2E message report: AI summary + "What to do now"; per-finding `recommendation` | — |
| M3-4 | DONE | Strength badges + legend on report page (browser); `test_message.py::test_llm_unknown_ids_dropped_and_strength_forced_heuristic` | — |
| M3-5 | DONE | `test_audit_messages.py::test_wording_alone_never_high_risk` (6 rows); `test_risk.py::test_heuristics_alone_never_exceed_suspicious` | `dd67209` |
| M3-6 | DONE | `test_audit_messages.py::test_benign_real_format_messages_not_flagged` (OTP short + long, debit alert, delivery) | `dd67209` |

### M4 correlation

| ID | Status | Evidence | Fix |
|---|---|---|---|
| M4-1 | DONE | Domain (incl. final redirect hop), cert, email, phone, UPI, crypto cluster; IP/ASN/NS → CORR.SHARED_INFRA only. **Gap fixed:** message reports did not carry their links' hop domains, so different links to one destination never clustered | `c50dda0` |
| M4-2 | DONE | CORR.SIMILAR_MESSAGE: word 3-shingle Jaccard ≥ 60% on redacted, tokenised text (`correlation/similarity.py`); `test_similarity.py` | — |
| M4-3 | DONE | `/trends/impersonation` now counts techniques per brand; `test_audit_correlation.py::test_trends_group_by_brand_and_technique`; browser shows "How: lookalike domain (5), fake login page (3)…" | `c50dda0` |
| M4-4 | DONE | `Cluster.edges` with reason per pair; browser "Why these reports are linked (6)" | `c50dda0` |
| M4-5 | DONE | `test_audit_correlation.py::test_three_bank_messages_different_links_same_destination_form_one_cluster`, `test_three_messages_same_upi_payee_form_one_cluster`; summary optional (`summary is None` without LLM) | `c50dda0` |

### M5 website security assessment

| ID | Status | Evidence | Fix |
|---|---|---|---|
| M5-1 | DONE | Headers/mixed content/old TLS: `test_rdap_headers.py`. Added POSTURE.INSECURE_COOKIE, CORS_WILDCARD_CREDENTIALS, NO_HTTPS_REDIRECT: `test_audit_posture.py` (first 4 tests). Suspicious redirects: REDIRECT.* | `2e48af4` |
| M5-2 | DONE | Only `/.git/HEAD` and `/.env`, behind proof of ownership: `test_attacker_review.py::test_owns_site_without_proof_is_refused_and_rate_limited`, `test_ownership_proof_unlocks_the_probe_for_that_domain_only` | — |
| M5-3 | DONE (scoped) | POSTURE.KNOWN_VULNERABLE_COMPONENT via osv.dev through `api_client`; recorded fixture `fixtures/osv/jquery-1.12.4.json` (4 GHSA/CVE); `test_osv_lookup_maps_versions_to_advisory_ids`, `test_detect_exact_versions_only` (partial version → nothing). OSV has no ecosystem for nginx/Apache/WordPress core (probed live), so server banners stay on the end-of-life table | `2e48af4` |
| M5-4 | DONE | `test_audit_posture.py::test_every_posture_id_is_reported_with_all_fields` (title, evidence+source, impact, severity, recommendation, limitation). No schema change needed: `Finding` already had them | `2e48af4` |
| M5-5 | DONE | `app/ownership.py`: DNS TXT `_cybermatrix-verify` or `/.well-known/cybermatrix-verify.txt`; documented in RISK_ENGINE.md §6 and ARCHITECTURE limitation 1; tests above | — |
| M5-6 | DONE | `test_audit_posture.py::test_posture_findings_score_zero_and_never_trigger_r3` (every POSTURE ID, as critical/authoritative ×3 → score 0, low_risk) | `2e48af4` |

### M6 decentralised threat intel

| ID | Status | Evidence | Fix |
|---|---|---|---|
| M6-1 | DONE | Indicators (report); campaign: `POST /clusters/{id}/register` + `GET /campaigns/{id}` (`test_a_cluster_can_be_registered_as_a_campaign_and_verified`, includes `/verify` MATCH and tamper); user-written summary (`incident_summary`, redacted, omitted from canonical bytes when empty: `test_incident_summary_is_redacted_committed_and_old_hashes_unchanged`); fingerprint + per-evidence SHA-256 (`GET /reports/{id}/evidence`, `test_evidence_manifest_hashes_each_item_reproducibly`). Browser: fingerprint, "Evidence references (7)", "Register this campaign on-chain" render. Campaign registration was **not** sent to Sepolia (fake chain in tests) | `00602e4` |
| M6-2 | DONE | parentHash revisions: `test_api.py::test_reassess_registers_a_revision_and_supersedes_the_parent`; verify.py (no backend) MATCH; `/verify`; dispute: `test_dispute_reason_is_redacted_and_wallet_ready` + UI; validator set-status: new `ValidatorPanel` (wallet `eth_call isValidator`, `setStatus`). The validator panel and dispute were **not** exercised with a real wallet this session | `00602e4` |
| M6-3 | DONE | EIP-712 `ReportAttestation` (`app/registry/attest.py`), chosen over direct submission (no user gas, registry stays permissioned); trade-off in ARCHITECTURE limitation 4. `test_audit_registry.py::test_user_signature_is_verified_stored_and_shown`, `test_forged_or_mismatched_signatures_are_rejected` | `00602e4` |
| M6-4 | DONE | Decoded calldata + log of the real submit and setStatus txs: only reportHash, parentHash (zero), id, status (`docs/evidence/onchain.md`). `test_audit_security.py::test_salt_prevents_recovering_the_url_from_the_onchain_hash` | `abe648d` |
| M6-5 | DONE | `VerificationResult.note`, verify.py output ("does not prove the report's conclusions are true"), registry panel text, ARCHITECTURE "what the chain does and does not prove" | `00602e4` |
| M6-6 | DONE | ARCHITECTURE: "Validator authority is ours … `CORR.VALIDATED_MATCH` is authoritative only in the sense that our own validator reviewed the earlier report" | `00602e4` |

### RC risk classification

| ID | Status | Evidence | Fix |
|---|---|---|---|
| RC-1 | DONE | 5 classes in `RiskClass`; grep of frontend/extension: "safe" only in "never safe"/Safe Browsing. **Gap fixed:** the explanation filter let "is secure", "looks clean" through; `test_audit_security.py::test_reassuring_explanations_are_rejected` (8) / `test_factual_wording_is_allowed` (4) | `abe648d` |
| RC-2 | DONE | Browser (eMudhra report): class, score, confidence, coverage + unavailable checks, timestamp ("Checked"), findings with source, actions, limitations; indicators section added | `007410a` |
| RC-3 | DONE | R5 text; limitation "Absence of threat-intel listings does not prove safety"; `FindingGroups` empty state | — |
| RC-4 | DONE | `test_risk.py::test_rules[R2 authoritative high counts as >= technical (RC-4)]`; RISK_ENGINE.md R2 row updated | `29c4519` |
| RC-5 | DONE | `test_risk.py::test_rules` (21 rows R1–R5 + near misses), heuristic cap, allowlist dampening, abusable host, brand-in-path, redirect dampening tests | `29c4519` |

### SEC security and privacy

| ID | Status | Evidence | Fix |
|---|---|---|---|
| SEC-1 | DONE | `test_safe_fetch.py::test_blocks_before_any_network` (35 URLs incl. decimal/octal/hex, IPv6, mapped, NAT64, ULA, metadata, now %-encoded hosts), `test_any_private_address_in_answer_blocks`, `test_ipv4_mapped_v6_in_dns_answer_blocked`; rebinding: `test_security_review.py`; 36 cases in `test_attacker_review.py` | `5b6d772` |
| SEC-2 | DONE | `test_safe_fetch.py::test_public_redirect_to_private_is_blocked`, `test_tls_retry_reruns_precheck_and_blocks_private` | — |
| SEC-3 | DONE | `test_body_cap`, `test_content_length_cap`, `test_gzip_bomb_capped`, `test_non_html_rejected`; QR: `test_audit_security.py::test_qr_decompression_bomb_and_size_cap_rejected` (400 MP PNG → 422) | `abe648d` |
| SEC-4 | PARTIAL (documented) | No separate fetch container. ARCHITECTURE limitation 24 states it, the in-code mitigations, and the fix | `88d0b8d` |
| SEC-5 | DONE | `test_audit_security.py::test_forwarded_for_ignored_unless_proxy_trusted`, `test_rotating_spoofed_forwarded_for_does_not_reset_the_limit`; per-check timeouts `pipeline.run_check` (`test_pipeline.py`) | `abe648d` |
| SEC-6 | DONE | `test_audit_security.py::test_injection_does_not_change_class_and_is_flagged`; E2E message: `injection_attempt_detected: true` | `abe648d` |
| SEC-7 | DONE | `test_audit_security.py::test_no_pii_in_any_outbound_payload` (every byte to the LLM, GSB, URLhaus, VT; name, OTP, account, Aadhaar, PAN, phone, email). Name limitation stated in message reports and ARCHITECTURE limitation 6 | `abe648d` |
| SEC-8 | DONE | UI grep: no copy asks for secrets. New warning when pasted text looks like a password/PIN/private key/seed phrase (`lib/detect.ts::looksLikeSecret`, spot-checked 4 yes / 4 no) | `c383d12` |
| SEC-9 | DONE | `test_audit_security.py::test_report_ids_are_uuid4_and_shared_views_hold_no_message_text` (+ STIX/blocklist/trends); **bug found in the browser and fixed:** the recipient's own address from pasted headers (`To:`) appeared on `/clusters`; `test_recipient_address_in_pasted_headers_is_never_an_indicator` | `cef4ec6` |
| SEC-10 | DONE | Backend container log after the full E2E + seed run: 0 occurrences of any `.env` value, 0 of message text/phone. `.env` gitignored; `.env.example` now lists all 8 missing variables | `6d1f914` |
| SEC-11 | DONE | Same filter as RC-1; UI layout footer "No result is a guarantee…" | `abe648d` |

### MVP (§7)

| Item | Evidence |
|---|---|
| URL analysis | E2E URL + bare domain; `test_url_checks.py` |
| Phishing detection | Demo seed paypa1 (R1), `test_pipeline.py` |
| TLS analysis | eMudhra report; `test_tls_chain.py`; live badssl |
| AI evidence-grounded explanation | E2E URL case: Gemini summary, `ai_refs_not_in_report: []`; `test_message.py::test_injection_cannot_change_verdict_or_say_safe` |
| Scam detection | E2E message; `test_audit_messages.py`; ScamShield held-out 36/38 (TESTING.md) |
| Risk assessment | `test_risk.py` |
| ≥1 TI source | 4 live (Phase 0.5) |
| On-chain registry | Sepolia v3, 2 reports registered |
| Independent verification | verify.py MATCH/MISMATCH; `/verify` tests |
| Functional dashboard | `/investigate`, `/report`, `/clusters`, `/verify`, `/watch`, `/org` built and the first three checked in the browser |
| ≥3 suspicious + ≥3 benign | Demo seed: 3 malicious/suspicious URLs + scam SMS; 3 low_risk URLs + benign OTP (`test_demo_seed.py`); plus 4 benign messages (`test_audit_messages.py`) |

### Out of scope (§13)

| Item | Status |
|---|---|
| No antivirus claims / "detects every attack" / guaranteed wording | Grep clean (frontend, extension, LLM prompts); footer disclaims guarantees |
| No model training | None in repo |
| No exploitation / reproduction of real vulnerabilities | eMudhra keys never used; fixtures hold public certs only |
| No unauthorised scanning | Exposed-file probe needs proof of ownership; everything else passive |

## Phase 2: deliverable readiness (prerequisites only)

| ID | Status | Evidence / what's missing |
|---|---|---|
| D-1 | READY | Clean clone builds and runs with no `.env` (all services healthy) and with the filled `.env` |
| D-2 | **NOT READY** | History clean (Phase 0.6). **No LICENSE file and no root README.** Setup commands in CLAUDE.md/TESTING.md were run this session and work. Licence choice is yours |
| D-3 | READY | E2E URL report: Gemini explanation cites only check IDs present. For a *message* demo, Gemini output on the E2E messages fell back to the rule-based summary (one had an injection, by design); pick a message without injection text for the AI demo |
| D-4 | READY | `esign-verify.in` (eMudhra fixture) + the GSB test URL, both with TLS analysis |
| D-5 | **NOT READY** | Address, verified source and submit + setStatus tx hashes exist. **No dispute transaction exists on any registry version** (checked Etherscan tx lists for v3 and v2). Needs one bonded `disputeReport` (0.001 Sepolia ETH) from a wallet, then a `setStatus` to resolve it |
| D-6 | READY | `docs/evidence/verify_match.txt`, `verify_mismatch.txt` |
| D-7 | READY | ARCHITECTURE: pipeline diagram, TI data-sharing table (GSB `urls.search` sends raw URLs), security methodology, limitations; RISK_ENGINE updated for every new check; TESTING.md numbers re-observed |
| D-8 | — | The requirement text ended at "D-8" with nothing after it |
