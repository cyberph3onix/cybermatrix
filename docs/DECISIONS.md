# Design decisions & prior art

What we reused, what we borrowed as ideas, and what we deliberately left out. Researched 2026-11-08.

## Reused (libraries)

| Need | Choice | Why | Rejected |
|---|---|---|---|
| SSRF-safe fetching | `httpx-secure` 2.x (0BSD), pinned version, wrapped by our redirect loop and caps | Async httpx, validates with `is_global`, connects to the exact validated IP (defeats DNS rebinding), and no fallback to an unvalidated hostname | `safe-outbound`: beta, sync-only httpx client that doesn't pin the socket; writing our own from scratch: hours of edge cases |
| Lookalike domains | `dnstwist` as a library, permutations precomputed per brand | Mature permutation engine (homoglyph, bitsquat, insertion, transposition…); a precomputed set makes lookup O(1) | Pure edit distance only: misses homoglyphs |
| TLS chain validation | `sslyze` certificate_info + `cryptography` | Validates against several root stores, not just one | Hand-rolled validation |
| Certificate Transparency | Cert Spotter issuances API, crt.sh fallback | Cert Spotter returns `pubkey_sha256`, issuer and revocation; crt.sh is undocumented, heavily rate-limited and often returns 502s | crt.sh as primary |

## Threat-intel sources

- **Google Safe Browsing v5 `urls.search`**: current API; non-commercial use only (the commercial path is Web Risk).
  Roadmap: switch to `hashes.search` so only 4-byte hash prefixes leave our server, not raw URLs.
- **URLhaus** (auth key), **OpenPhish** public feed (downloaded and matched locally, so no URL leaves the server),
  **VirusTotal** (free tier; ≥ 5 engines treated as authoritative).
- **OpenPhish feed URL:** `openphish.com/feed.txt` now 302-redirects to `raw.githubusercontent.com/openphish/public_feed/…`.
  Our API client never follows redirects (and treats a 3xx as a failure), so we download the target directly.
  Refreshed on startup and every 6 h; the last file is kept if a download fails, and a feed older than 48 h
  makes the check `unavailable` rather than silently stale.
- **Host-level matches are gated.** URLhaus and OpenPhish also match on the host. That is skipped for
  allowlisted (Tranco / official) and abusable hosts, because `risk.dampen` never drops threat-intel findings and
  one malicious file on github.com would otherwise mark every GitHub URL `confirmed_malicious`. Exact-URL matches
  always count.
- **VirusTotal is lookup-only.** A URL VT has never seen is not submitted for scanning (that would publish it, and
  the free tier allows 4 requests/min). A 404 is a completed check with no finding.
- **Intel lookups cover the redirect destination too** (submitted URL first, then the final URL once the redirect
  chain is known), so a shortener pointing at a listed page is caught. Responses are cached in Postgres for 6 h,
  keyed by a SHA-256 of the lookup.
- **RDAP** uses the IANA bootstrap file (cached 24 h) to find each TLD's server; only `https` servers are used.
- **PhishTank: not used.** New registrations have been closed since 2020 and remained closed as of mid-2026.

## The eMudhra incident (Module 2)

- On 2026-10-17, eight eMudhra intermediate CA keys (P-384) were found to be computable from their public certs
  because of a flawed key-generation ceremony (CVE-2026-111943). Six are TLS intermediates (EM DV/OV/EV TLS CA -
  G3B/G3C), and Sectigo cross-signed copies also exist. Browsers blocked them within hours, and Mozilla removed
  emSign ECC Root CA - G3.
- **Our approach:** a curated list matched by cert SHA-256 **and SPKI SHA-256** (SPKI catches the cross-signs),
  plus a removed-root rule.
- **Why it matters:** programs that bundle their own roots (Python certifi, Go binaries, containers) don't get
  browser CRLSet/OneCRL updates. An explicit distrust check covers that gap.
- **What we do NOT claim:** we cannot detect a CA's key-generation weakness from a URL. We flag known-compromised
  CAs from authoritative lists.
- **What we do NOT do:** sign anything with the recovered keys. Demos use fixture chains containing the real
  public intermediate certs. Chrome found no TLS certs from these intermediates in CT before the block, so no live
  site exists to demo against.

## Borrowed ideas

- **PhishLLM (USENIX Security '24):** brand recognition and "is this page collecting credentials" are language
  tasks an LLM does well. We use the LLM only to *extract* the claimed brand and intent. Deterministic code then
  checks domain ownership against brands.json, and an LLM-only brand claim stays heuristic.
- **phishing_catcher (x0rz):** weighted suspicious-keyword and TLD scoring on new CT certificates. We use the
  idea for `URL.KEYWORDS` / `DOMAIN.SUSPICIOUS_TLD` and for the optional "suspicious certificate issuance"
  monitor. We write our own lists rather than copying its data files.
- **Ethereum Attestation Service:** linked attestations and revocation. Our `parentHash` and status machine follow
  the same idea. We use our own contract because the brief requires a deployed smart contract and judges score
  the registry design.

## Deliberately out of scope

- Headless-browser capture (Lookyloo-style) and screenshot/visual brand models (Phishpedia-style): they need JS
  execution, which conflicts with our no-JS safety rule, and the 48-hour budget.
- Training models: the brief says not to, and nothing here needs it.

## Evaluation data

- **ScamShield-IN** (Hugging Face, ~8k Indian SMS, fraud/legit labels plus fraud types such as OTP, UPI and KYC;
  licence tag openrail). Labels are noisy, so we hand-verify a 50-message sample (25 fraud, 25 legit, including
  real-but-urgent bank OTP messages) and report per-class results in docs/TESTING.md.
- **URLs:** badssl.com subdomains for TLS failures, recorded OpenPhish/URLhaus entries (frozen as fixtures),
  and top Indian bank, government and university sites as benign.

## LLM provider: Gemini preferred, Anthropic fallback
The user supplied a Gemini key, so `default_llm()` picks `GeminiLlm` (REST, `responseJsonSchema`, key in the
`x-goog-api-key` header) when `GEMINI_API_KEY` is set, else `AnthropicLlm`. Everything that makes the boundary safe
(redaction, `<untrusted_input>`, schema validation, dropped unknown check_ids, forced heuristic strength, injection
detection) sits outside the client, so it is unchanged. Redacted text now goes to Google instead of Anthropic.

## GSB v5 responds in protobuf
Verified live (2026-11-09): `urls:search` returns binary protobuf and rejects `alt=json` / `$alt=json` with
"Unsupported Output Format", despite the REST docs showing JSON. `checks/intel/gsb.py` decodes the small message by
hand (`threats` = field 1, url = 1, threat_types = 2) and still accepts JSON if Google ever serves it.
