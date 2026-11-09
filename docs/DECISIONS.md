# Design decisions & prior art

What we reused, what we borrowed as ideas, and what we deliberately left out. Researched 2026-11-08.

## Reused (libraries)

| Need | Choice | Why | Rejected |
|---|---|---|---|
| SSRF-safe fetching | `httpx-secure` (0BSD, [repo](https://github.com/Zaczero/httpx-secure)), exact version pinned in `pyproject.toml`, wrapped by our redirect loop and caps | Async httpx, validates with `is_global`, connects to the exact validated IP (defeats DNS rebinding), and no fallback to an unvalidated hostname | `safe-outbound`: beta, sync-only httpx client that doesn't pin the socket; writing our own from scratch: hours of edge cases |
| Lookalike domains | `dnstwist` as a library, permutations precomputed per brand | Mature permutation engine (homoglyph, bitsquat, insertion, transposition…); a precomputed set makes lookup O(1) | Pure edit distance only: misses homoglyphs |
| TLS chain validation | `sslyze` certificate_info + `cryptography` | Validates against several root stores, not just one | Hand-rolled validation |
| Certificate Transparency | Cert Spotter issuances API, crt.sh fallback | Cert Spotter returns `pubkey_sha256`, issuer and revocation; crt.sh is undocumented, heavily rate-limited and often returns 502s | crt.sh as primary |

## Threat-intel sources

- **Google Safe Browsing v5 `hashes.search`** (default): only 4-byte SHA-256 prefixes of the spec's URL expressions
  leave our server; full hashes are matched locally. `GSB_MODE=urls` switches to `urls.search` (sends full URLs). No
  automatic fallback between them, because falling back would leak exactly the URLs that hit an error. Non-commercial
  use only (the commercial path is Web Risk) ([Safe Browsing overview](https://developers.google.com/safe-browsing);
  [`hashes.search`](https://developers.google.com/safe-browsing/reference/rest/v5/hashes/search): 4-byte prefixes;
  [`urls.search`](https://developers.google.com/safe-browsing/reference/rest/v5/urls/search)).
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
  the public API allows 4 requests/min and 500/day, [VirusTotal docs](https://docs.virustotal.com/reference/public-vs-premium-api)). A 404 is a completed check with no finding.
- **Intel lookups cover the redirect destination too** (submitted URL first, then the final URL once the redirect
  chain is known), so a shortener pointing at a listed page is caught. Responses are cached in Postgres for 6 h,
  keyed by a SHA-256 of the lookup.
- **RDAP** uses the IANA bootstrap file (cached 24 h) to find each TLD's server; only `https` servers are used.
- **PhishTank: not used.** Its registration page says "New user registration temporarily disabled" (checked
  2026-11-10, [phishtank.org/register.php](https://phishtank.org/register.php)); Wikipedia dates the closure to 2020.

## The eMudhra incident (Module 2)

- On 2026-10-17 (20:06 UTC) a researcher reported to Mozilla that the private keys of eight eMudhra intermediate
  CAs (NIST P-384) could be recovered from their public certificates, the result of a faulty key-generation
  ceremony in April 2025. Six are TLS intermediates (EM DV/OV/EV TLS CA - G3B/G3C) and two are code signing; Sectigo
  cross-signed copies also existed. Mozilla blocked them through OneCRL the same evening (22:59 UTC), eMudhra revoked
  all eight on 2026-10-18, Sectigo revoked the cross-signs on 2026-10-19, and Mozilla emergency-distrusted emSign ECC
  Root CA - G3 on 2026-10-20 (NSS 3.131.1). The Go project assigned CVE-2026-111943 (GO-2026-6809, a `crypto/x509`
  denylist). Sources: [Mozilla Security Blog](https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/),
  [Kudelski timeline](https://kudelskisecurity.com/research/emudhra-intermediate-ca-private-key-compromise),
  [Go vulnerability database](https://pkg.go.dev/search?q=CVE-2026-111943&m=vuln),
  [eMudhra statement](https://emudhra.com/en/post/certificate-security-incident).
- **Our approach:** a curated list matched by cert SHA-256 **and SPKI SHA-256** (SPKI catches the cross-signs),
  plus a removed-root rule.
- **Why it matters:** programs that bundle their own roots (Python certifi, Go binaries, containers) don't get
  browser CRLSet/OneCRL updates. An explicit distrust check covers that gap.
- **What we do NOT claim:** we cannot detect a CA's key-generation weakness from a URL. We flag known-compromised
  CAs from authoritative lists.
- **What we do NOT do:** sign anything with the recovered keys. Demos use fixture chains containing the real
  public intermediate certs. The Chrome Root Program reported that no TLS certificate chaining to the six intermediates had
  appeared in CT before the block ([as reported by The Hacker News](https://thehackernews.com/2026/10/eight-emudhra-ca-keys-compromised.html)), so no live
  site exists to demo against.

## Borrowed ideas

- **PhishLLM (Liu et al., USENIX Security '24, [paper](https://usenix.org/conference/usenixsecurity24/presentation/liu-ruofan)):** brand recognition and "is this page collecting credentials" are language
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

- **ScamShield-IN** ([Hugging Face](https://huggingface.co/datasets/haxrits/ScamShield-IN), 8,066 Indian SMS, fraud/legit labels plus fraud types such as OTP, UPI and KYC;
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
