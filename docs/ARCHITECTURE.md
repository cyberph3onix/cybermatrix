# Architecture

See CLAUDE.md for the module map and docs/RISK_ENGINE.md for rules R1–R5 and the check catalogue. This file gives the
security methodology, records the outcome of the attacker review (Session F), and lists what is still open.

## Security methodology

**Pipeline.** Input is classified (link, domain, email, message, QR). Links go through `safe_fetch` (SSRF-guarded,
pinned IP, manual redirects, size and time caps, no JavaScript) and the checks run concurrently with per-check
timeouts: URL structure and lookalikes, redirects, page content, TLS chain / revocation / CT, RDAP age, DNS
(DNS-over-HTTPS), and four threat-intel sources. Messages get indicator extraction, redaction, wording signals and
the link pipeline for every link they contain. Correlation compares indicators and message wording with stored
reports. `engine/risk.py` then classifies with rules R1–R5; the LLM only explains and extracts.

**Evidence model.** Every finding carries evidence with a source and a strength (authoritative, technical,
heuristic). Heuristics are capped at 30 points, so wording alone never exceeds `suspicious`. Security-posture items
(headers, email authentication, end-of-life software, exposed files) never affect the phishing class. Coverage and
limitations are part of every report; the best class is `low_risk`, never "safe".

**Threat intelligence.** Google Safe Browsing v5 (hash prefixes only), URLhaus, OpenPhish (local feed), VirusTotal
(lookup only, ≥ 5 engines = authoritative), the eMudhra distrust list (cert and SPKI SHA-256), Cert Spotter / crt.sh,
RDAP and DNS-over-HTTPS. Host-level intel matches are skipped on allowlisted and abusable hosts.

**Trust boundaries.** Untrusted text reaches the LLM only redacted and inside `<untrusted_input>`; outputs are
schema-validated and unknown check IDs dropped. Active requests to a site beyond the page fetch (`/.env`, `/.git`)
need DNS or file proof of ownership. On-chain data is a hash commitment only, with a random salt.

**Validation.** 490+ offline tests (recorded fixtures), 61 Foundry tests at 100% branch coverage, the demo seed
(≥ 3 benign and ≥ 3 malicious cases) and the ScamShield-IN evaluation with held-out numbers (docs/TESTING.md).

## Attacker review: what was tried and what changed

Tests for every item are in `backend/tests/test_attacker_review.py`.

| Attack | Result |
|---|---|
| SSRF via alternate IP encodings (decimal, octal, hex, Unicode digits, ideographic dots, trailing dot), IPv6 forms (mapped, compatible, NAT64, SIIT, ULA, link-local, documentation range), cloud metadata addresses and hostnames, userinfo and backslash confusion | Already blocked; 36 new cases lock it in |
| DNS rebinding | One lookup per hop. *Correction from the second review:* the connection was not actually pinned; see below |
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

## Second hostile review

Tests for every item are in `backend/tests/test_security_review.py`, `verify/tests/test_verify.py` (forged-report
cases) and `contracts/test/ThreatRegistry.t.sol` (reporter-role cases). Each failed before its fix.

| Attack | Result |
|---|---|
| DNS rebinding past `safe_fetch` | **Fixed.** We validated our own lookup but handed httpx-secure the *hostname*. It resolved again and opened a TCP probe to the second answer before validating it, so a rebinding DNS server could make us connect to `127.0.0.1:443` or any internal host on 80/443/8080/8443 (connect only; no HTTP was sent). The request now names the validated IP; Host, SNI and certificate checks use the hostname |
| Closing `</untrusted_input>` from inside a message or page | **Fixed.** Untrusted text could end the data block and carry on as instructions. `ai.llm.untrusted()` strips tag look-alikes before wrapping; every LLM call uses it |
| Page text reaching the trusted part of the explainer prompt | **Fixed.** Finding titles quote page titles, LLM-extracted brand names and domains, and they sat in the trusted JSON. They now go inside the untrusted block; the trusted part has only IDs and enums |
| Injected text making the explanation reassure the user | **Fixed.** Only the word "safe" was blocked, so "legitimate, go ahead and log in" got through on a `high_risk` report. Reassuring wording (legitimate, genuine, harmless, no risk, go ahead…) now falls back to the rule-based summary. When an injection is detected, the model's prose is never used |
| PII reaching the LLM | **Fixed.** `(555) 123-4567`, `555-123-4567` and `555.123.4567` leaked six of ten digits; `name [at] host [dot] com`, `name(at)host(dot)in` and `name at host dot com` leaked entirely |
| Legit top site → `high_risk` | **Fixed.** `outlook.office365.com` (Outlook web login) was **`high_risk`**: `URL.BRAND_IN_SUBDOMAIN` + `PAGE.CREDENTIAL_FORM`, both high, because office365.com wasn't listed as Microsoft's. Added Microsoft's own domains, plus a structural rule: on a top-10k host whose domain label *is* one of the brand's labels, that brand's name in the subdomain or page title is the brand's own site |
| Legit top site → `suspicious` | **Fixed.** `amazon.co.uk/ap/signin` came out suspicious (`PAGE.CREDENTIAL_FORM`, same cause). SSO forms posting between two allowlisted sites (`youtube.com` → `accounts.google.com`) fired `PAGE.FORM_ACTION_CROSS_DOMAIN` (high). A server that omits its intermediate certificate got `TLS.UNTRUSTED_ROOT` (high) on top of `TLS.INCOMPLETE_CHAIN`. Any of these plus one more high finding made `high_risk` |
| `TLS.NO_HTTPS` with no evidence | **Fixed.** An `http://` link whose fetch timed out was reported as "served over plain HTTP". The check is now `unavailable` unless a page was actually served |
| Framing a victim site via a validated report | **Fixed.** Domain indicators include every redirect hop, so a phishing URL that 302s to `victim.com`, once validated, made `victim.com` `confirmed_malicious` through `CORR.VALIDATED_MATCH`. Three such suspicious reports gave it `CORR.PRIOR_REPORTS`. A prior report's domain now counts only if it was the host of a URL that was submitted (or appeared in a submitted message) |
| Forged report "verifying" | **Fixed.** Anyone can call `submitReport` with the hash of a report.json they wrote (say, "google.com is confirmed_malicious"). verify.py and `/verify` printed MATCH. Now `submitReport` is restricted to reporters the owner authorised (`NotReporter` otherwise), so a stranger can't register anything. As defence in depth, `/verify` also requires our relayer as the reporter, and verify.py checks `isReporter` on-chain and takes `--relayer` (`UNTRUSTED_REPORTER` on a mismatch) |
| Front-running a registration | **Fixed.** Copying our pending tx's hash and submitting it first made the attacker the reporter, who could then supersede it. Only authorised reporters can submit now, so the copied transaction reverts. The relayer also refuses to adopt a record it didn't create (`HashClaimedByAnotherReporter`) |
| Dispute griefing loop | **Priced by v2.** Re-disputing a re-validated report is still allowed, but each round forfeits the 0.001 ETH bond to the owner (limitation 2). The reporter role is registry v3 at `0x5De4Cd6F651A4D80ddA16fc70431dd669621BeeA` (source verified); v1 and v2 are retired |
| Hash mismatch backend ↔ verify.py | None found. Lone surrogates are rejected at the boundary (422), floats and big ints aren't in the schema, and stored bytes are served verbatim |
| IPv6 / alternate encodings / redirect tricks | Nothing new got through. The first review's 36 cases still pass |

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
   a user, and the contract owner, validators and reporters are fully trusted. Since v3 the registry is permissioned:
   only reporters the owner added can submit. That is what makes a MATCH mean "CyberMatrix registered this", but
   nobody else can publish to it.
5. **Rate limits are in-process (accepted).** They assume one backend instance; a shared store such as Redis is the fix
   for a multi-instance deployment. Several instances, or a proxy that is not trusted
   (`TRUST_FORWARDED_FOR`), weaken them.
6. **Redaction is pattern-based.** Names can only be caught after a salutation, sign-off, "my name is" or "This is X Y
   from"; names in capitals, postal addresses and free-form identifiers aren't detected. Digits written as words, or
   split by letters, aren't caught. Short digit groups (e.g. a 3-digit area code on its own) can survive. The LLM
   sees only the redacted text, but redaction can miss things. Separately, links found in a message go to the
   threat-intel APIs unredacted (they need the exact URL), query string included.
7. **Prompt-injection defence is structural.** Injection cannot change a classification. It can still add heuristic
   `MSG.*` signals (capped, so at most `suspicious`) or bias a summary in ways the wording filter misses.
   Injection detection is a regex, so a rephrased attempt isn't flagged and the model's prose is used. Tag look-alikes
   built from Unicode confusables (`＜/untrusted_input＞`) aren't stripped.
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
13. **A leaked relayer key can register forged reports.** Submission is restricted to authorised reporters, so the
    relayer key is now what an attacker needs. The owner can `removeReporter`; reports it already registered stay on
    chain and verify.py then flags them ("no longer authorised"). Keep the key out of logs and rotate it if exposed.
14. **Verification trusts one relayer address.** `/verify` and `verify.py --relayer` accept only the current relayer.
    Rotating `RELAYER_PRIVATE_KEY` makes older reports verify as untrusted unless a list of past relayers is added.
    Without `--relayer`, `verify.py` accepts any reporter the registry currently authorises (`isReporter`); against
    an older registry without that role it still says MATCH with a warning.
15. **Crowd-sourced correlation can be gamed.** Two crafted messages that mention `victim.com` with scam wording are
    enough for `CORR.PRIOR_REPORTS` (medium heuristic, so `suspicious`) on any domain outside the top 10k. The
    hop-domain hole is closed, but a submitted URL or message really does name the domain. A per-submitter identity or
    distinct-source threshold would be needed. A *validated* message that names a victim's URL still makes that
    domain `confirmed_malicious`: that rests on validator judgement.
16. **Incomplete chains hide untrusted roots.** We don't fetch missing intermediates (no AIA chasing), so when a server
    omits its intermediate we report `TLS.INCOMPLETE_CHAIN` with a "could not confirm" limitation instead of
    `TLS.UNTRUSTED_ROOT`. A private-CA leaf served alone is therefore not flagged as untrusted.
17. **The brand's-own-label rule trusts Tranco.** A top-10k domain whose label equals a brand label (`amazon.co.uk`) is
    treated as that brand's own site for subdomain and page-title claims. A top-10k site that happens to share a
    brand's label but isn't the brand would escape those two checks. Threat intel and TLS still apply.
18. **Brand words in a top site's subdomain still count.** `apple.stackexchange.com` gets `URL.BRAND_IN_SUBDOMAIN`
    (high, so `suspicious`) because the spec never dampens subdomain matches. Changing that is a spec decision.
19. **Decompression is capped per read, not per byte.** The 2 MB cap is checked after each decoded chunk, so one 64 KB
    gzip read can briefly inflate to ~64 MB before the fetch is cut off. httpx would also decode Brotli/zstd if those
    packages were ever installed, with a higher ratio.
20. **Real-time protection sees browsing history.** With it on, the extension sends the address of every page opened
    to the API. The server neither stores nor logs it and never fetches the page, but whoever runs the API could.
    It is off by default, and only a quick check runs (no page content, certificate or redirect checks), so a
    phishing page on a fresh, unlisted domain with no lookalike pattern passes as `inconclusive`.
21. **Screenshots can't be redacted.** Text is masked before the LLM (rule 8); a screenshot is sent as an image, so
    names or balances in it reach the AI provider. The route requires explicit consent, the image is re-encoded
    (metadata stripped, at most 1280 px) and never stored, and the UI asks users to crop personal details. The
    brand reading is an AI judgement, so the finding is heuristic and alone never goes past `suspicious`.
22. **The feed is only as good as this server's reports.** It lists links from reports at `high_risk` or worse.
    A wrong report stays listed until a validator rejects it on-chain. Allowlisted sites are never listed, but a
    small legitimate site that was wrongly flagged can be.
23. **The org dashboard trusts its link.** Like CT watches, the dashboard id is a bearer token with no login. All it
    shows is derived from public information, and impersonation counts cover reports on this server only.

