# Architecture

See CLAUDE.md for the module map and docs/RISK_ENGINE.md for rules R1–R5 and the check catalogue. This file records
the outcome of the attacker review (Session F) and what is still open.

## Attacker review: what was tried and what changed

Tests for every item are in `backend/tests/test_attacker_review.py`.

| Attack | Result |
|---|---|
| SSRF via alternate IP encodings (decimal, octal, hex, Unicode digits, ideographic dots, trailing dot), IPv6 forms (mapped, compatible, NAT64, SIIT, ULA, link-local, documentation range), cloud metadata addresses and hostnames, userinfo and backslash confusion | Already blocked; 36 new cases lock it in |
| DNS rebinding | One lookup per hop, validated address pinned for the connection |
| Redirect to an internal address, scheme or port | Blocked on every hop (existing tests) |
| Lone surrogate in a request body | **Fixed.** FastAPI echoed the input into its 422 body, which then failed to encode (HTTP 500). A custom handler returns location and message only |
| NUL byte in input | **Fixed.** Stripped at the request boundary (Postgres text columns reject it) |
| PII reaching the LLM | **Fixed.** Redaction missed lowercase PAN, IFSC, CVV, GSTIN, passport, vehicle numbers, dates, IP addresses, digits split by spaces, names after sign-offs and long path tokens in URLs. All now masked; page text is redacted too |
| LLM output changing the verdict | Not possible by construction (it can only add heuristic findings, capped at a score of 30, so never above `suspicious`). Tests feed it hostile output and injected text |
| Backend and verify.py hash disagreement | None found. Canonical bytes round-trip, including odd Unicode, and the verify.py function matches the backend on the sample report |
| Legitimate top site rated badly | **Fixed.** A partner or payment logo on an allowlisted site's login page produced `suspicious`. On allowlisted hosts a logo alone no longer counts as a brand claim; the page title and og:site_name still do |
| Rotating IPs to drain the relayer's gas | **Mitigated.** Server-wide cap of `REGISTER_MAX_PER_HOUR` (default 30) on new registrations, on top of the per-IP limit |
| Using "I own this site" to probe someone else's `/.env` | **Mitigated, not solved.** Own limit of 3 per minute per IP; see below |
| Contract state machine | 46 Foundry tests pass; findings below |

## Known limitations

1. **Ownership is not verified.** `owns_site` is a checkbox. Anyone can ask us to GET `/.git/HEAD` and `/.env` on a
   third-party site and publish whether they were readable (never the contents). Proper fix: DNS TXT or file-token proof.
2. **Disputes cost a bond (fixed in v2).** v1 let anyone knock a `Validated` report to `Disputed` for the price of
   gas. v2 (`0x46509457…BbB4`) requires exactly `disputeBond` (0.001 ETH) per dispute: a validator who rejects the
   report returns it, one who re-validates keeps it, and a revision by the reporter returns it. Payouts are pull-based
   (`withdraw`, balance zeroed before the transfer; a reentrancy test covers it). The bond prices abuse but does not
   stop a well-funded attacker; validators are still trusted. Disputes are sent from the user's wallet, never by the
   relayer, so the relayer cannot be drained.
3. **Registry status can lag.** `CORR.VALIDATED_MATCH` uses the status this server last saw; it refreshes when a
   report's registration is viewed, not continuously.
4. **Single relayer, single owner.** All reports register from one address, so the on-chain reporter does not identify
   a user, and the contract owner and validators are fully trusted.
5. **Rate limits are in-process.** They assume one backend instance. Several instances, or a proxy that is not trusted
   (`TRUST_FORWARDED_FOR`), weaken them.
6. **Redaction is pattern-based.** Names can only be caught after a salutation, sign-off, "my name is" or "This is X Y
   from"; addresses and free-form identifiers are not detected. Digits written as words, or split by letters, are not
   caught. The LLM sees only the redacted text, but redaction can miss things.
7. **No prompt-injection defence beyond structure.** Injection cannot change a classification, but it can make the
   explanation or the language signals worse. We flag obvious attempts and say so in the report.
8. **Correlation is local and weak by design.** It only sees reports stored on this server, and shared hosting makes
   infrastructure matches meaningless on their own, so those are low severity.
9. **RDAP and hosting platforms.** Domain age is looked up for the registered domain (`appspot.com`), so a brand-new
   site on an old hosting platform is not flagged as young.
10. **GSB v5 sends the full URL to Google** and is licensed for non-commercial use. A `hashes.search` client that
    sends only hash prefixes is the privacy-preserving alternative.
11. **UPI QR codes cannot be verified.** We only check whether the payee ID appeared in earlier reports.
12. **Passive only.** No JavaScript runs, so cloaked or script-built phishing pages can look clean.
