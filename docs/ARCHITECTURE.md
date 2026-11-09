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
| Using "I own this site" to probe someone else's `/.env` | **Fixed.** Needs a DNS-TXT or well-known-file proof of ownership (`app/ownership.py`); still limited to 3 probes per minute per IP |
| Contract state machine | 46 Foundry tests pass; findings below |

## Known limitations

1. **Ownership is proven (fixed).** The `/.git/HEAD` and `/.env` probe needs a grant from `POST /ownership/verify`,
   issued only after the domain shows our random challenge in a `_cybermatrix-verify` TXT record or at
   `/.well-known/cybermatrix-verify.txt` (a redirect to another domain does not count). Grants last 24 h and cover one
   registrable domain. Someone who controls a subdomain's web root but not DNS can still verify via the file, which
   matches how ACME HTTP-01 treats web-root control.
2. **Disputes cost a bond (fixed in v2).** v1 let anyone knock a `Validated` report to `Disputed` for the price of
   gas. v2 (`0x46509457…BbB4`) requires exactly `disputeBond` (0.001 ETH) per dispute: a validator who rejects the
   report returns it, one who re-validates keeps it, and a revision by the reporter returns it. Payouts are pull-based
   (`withdraw`, balance zeroed before the transfer; a reentrancy test covers it). The bond prices abuse but does not
   stop a well-funded attacker; validators are still trusted. Disputes are sent from the user's wallet, never by the
   relayer, so the relayer cannot be drained.
3. **Registry status lag is bounded (fixed).** A background job (`app/registry/sync.py`, every `REGISTRY_SYNC_S`,
   default 10 min) re-reads every non-terminal registration, so `CORR.VALIDATED_MATCH` lags the chain by at most one
   interval. Rows from the v1 contract keep their last status: their on-chain ids mean something else on v2.
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
9. **RDAP and hosting platforms (partly fixed).** RDAP only knows the platform (`pages.dev`, registered years ago). For
   sites on a private PSL suffix we now use the earliest certificate naming the site exactly in crt.sh's full CT history
   (`DOMAIN.YOUNG`, source `crt.sh`). Cert Spotter cannot be used for this: it lists unexpired certificates only. Sites
   served only under the platform's wildcard certificate (`*.github.io`) still have no age signal, and the report says so.
10. **GSB sends only hash prefixes (fixed).** The default `hashes.search` client canonicalises the URL, hashes the
    Safe Browsing host/path expressions and sends 4-byte prefixes; full hashes are matched locally (a prefix collision
    is not a hit). Verified live against Google's test pages. `GSB_MODE=urls` restores full-URL `urls.search`. Safe
    Browsing remains licensed for non-commercial use only.
11. **UPI QR codes cannot be verified.** We only check whether the payee ID appeared in earlier reports.
12. **Passive only.** No JavaScript runs, so cloaked or script-built phishing pages can look clean.
