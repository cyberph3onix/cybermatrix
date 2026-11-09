# Risk Engine Specification

The single source of truth for check IDs, severities and classification rules. Code in `engine/risk.py` must
implement exactly this; tests in `tests/test_risk.py` cover every rule.

## 1. Evidence strength

| Strength | Meaning | Who can emit it |
|---|---|---|
| `authoritative` | External authority says so: threat-intel listing, CA revocation, distrust-list match, match to an on-chain report with `Validated` status | Deterministic checks only |
| `technical` | Reproducible observation that indicates risk: expired cert, hostname mismatch, homoglyph of a protected brand, credential form posting cross-domain | Deterministic checks only |
| `heuristic` | Correlates with abuse but isn't proof: young domain, keyword in path, urgent language | Deterministic checks **and** the LLM (the LLM can emit nothing stronger) |

## 2. Scoring

Points by severity: critical 50, high 25, medium 10, low 3, info 0.

- **Heuristic points are capped at 30 in total.** Heuristics alone can reach `suspicious` but never `high_risk`.
  This is how we honour "a message should not be labelled fraudulent solely because it contains urgent language".
- `security_posture` findings contribute 0 points.
- Score is capped at 100.

## 3. Classification rules (evaluated in order, first match wins)

| Rule | Class | Condition |
|---|---|---|
| R1 | `confirmed_malicious` | Any finding with strength `authoritative` and severity `critical` |
| R1b | `confirmed_malicious` | Corroborated impersonation: (`URL.LOOKALIKE.HOMOGLYPH` or `URL.BRAND_IN_SUBDOMAIN`) **and** `PAGE.CREDENTIAL_FORM` **and** (`DOMAIN.YOUNG` or `TLS.CERT_VERY_NEW`) |
| R2 | `high_risk` | score ≥ 60, **or** any `critical` technical finding, **or** ≥ 2 `high` technical findings |
| R3 | `suspicious` | score ≥ 20, **or** any finding ≥ `medium` |
| R4 | `inconclusive` | coverage < 50% |
| R5 | `low_risk` | Otherwise. Display text: "No significant malicious indicators within the checks performed." |

Note that R3 fires before R4. A suspicious finding on low coverage stays `suspicious`, with low confidence.
`classification_reason` records the rule ID and the check IDs that triggered it, e.g. `"R1: URL.INTEL.GSB"`.

## 4. Coverage and confidence

Coverage = Σ weight(completed check groups) / Σ weight(applicable check groups) × 100 (integer).

| Check group | Weight (URL) |
|---|---|
| url.structure + lookalike | 10 |
| intel.gsb / intel.urlhaus / intel.openphish / intel.virustotal | 10 each (40) |
| fetch + redirects | 15 |
| page content | 10 |
| tls.chain + tls.revocation + tls.ct | 20 |
| domain.rdap + domain.dns | 5 (3 + 2) |

For messages: indicator extraction 20, LLM signals 30, and pipeline runs on extracted URLs 50. If there are no
URLs, that 50 is re-distributed proportionally.

Confidence:
- **high**: coverage ≥ 80 and (an authoritative finding, or ≥ 2 technical findings, or the class is `low_risk`)
- **medium**: coverage ≥ 50
- **low**: otherwise

## 5. False-positive controls

- **Allowlist dampening:** if the registrable domain is a protected brand's official domain or in the Tranco
  top 10k (and the host is not abusable, see below), drop `URL.LOOKALIKE.*`, `DOMAIN.*` and `URL.KEYWORDS`
  heuristics. **Never** drop TI or TLS findings, because legitimate sites get compromised.
- **Brand in path:** `URL.BRAND_IN_SUBDOMAIN` whose only match is in the *path* (e.g.
  `web.archive.org/web/…/sbi.co.in`) is dropped on allowlisted, non-abusable hosts. A match in the *subdomain* is
  never dampened. The finding's evidence records `match_location: subdomain | path`.
- **Redirects between a brand's own domains:** `REDIRECT.CROSS_DOMAIN` does not fire, and the hop does not count
  toward `REDIRECT.LONG_CHAIN`, when both registrable domains are official domains of the same brand
  (`sbi.co.in → sbi.bank.in`).
- **Redirects to allowlisted destinations:** `REDIRECT.CROSS_DOMAIN` is dropped when the *final* host is official
  or in the Tranco top 10k and not abusable (`bit.ly → amazon.in`). `bit.ly → evil.xyz` still fires.
  `REDIRECT.LONG_CHAIN` is never dampened.
- **Abusable hosts never get dampening:** `abusable_hosts.txt` (sites.google.com, docs.google.com/forms,
  forms.gle, firebaseapp.com, web.app, pages.dev, netlify.app, vercel.app, github.io, IPFS gateways,
  ngrok-free.app, blogspot.com …).
- Use `tldextract` with `include_psl_private_domains=True`, so `evil.github.io` ≠ `github.io`.
- VirusTotal: ≥ 5 malicious engines = authoritative; 1–4 = medium heuristic (single-engine hits are noisy).
- `TLS.INCOMPLETE_CHAIN` and old protocol versions are config issues (`tls_config`), not trust compromise.

## 6. Check catalogue

### URL / domain / page

| check_id | Category | Severity | Strength | Fires when |
|---|---|---|---|---|
| URL.INTEL.GSB | threat_intel | critical | authoritative | Google Safe Browsing v5 match (`hashes.search` full-hash match by default; `urls.search` with `GSB_MODE=urls`) |
| URL.INTEL.URLHAUS | threat_intel | critical | authoritative | URLhaus URL or host match (online or recent) |
| URL.INTEL.OPENPHISH | threat_intel | critical | authoritative | Exact URL or host in OpenPhish feed |
| URL.INTEL.VT_MAJORITY | threat_intel | critical | authoritative | VirusTotal ≥ 5 malicious engines |
| URL.INTEL.VT_MINORITY | threat_intel | medium | heuristic | VirusTotal 1–4 malicious engines |
| URL.LOOKALIKE.HOMOGLYPH | impersonation | high | technical | Confusable skeleton (UTS#39) equals a protected brand label; domain not official |
| URL.LOOKALIKE.TYPOSQUAT | impersonation | medium | technical | Damerau-Levenshtein ≤ 2 to brand label, or brand + affix (`sbi-kyc`, `hdfcbank-verify`) |
| URL.BRAND_IN_SUBDOMAIN | impersonation | high | technical | Brand's official domain/label appears in subdomain or path of an unrelated domain (`sbi.co.in.verify-now.xyz`) |
| URL.PUNYCODE_MIXED_SCRIPT | impersonation | high | technical | IDN label mixes scripts (Latin + Cyrillic, etc.) |
| URL.USERINFO_TRICK | phishing | high | technical | `@` in authority (`https://sbi.co.in@evil.tld`) |
| URL.IP_HOST | phishing | medium | technical | Host is a raw IP |
| URL.EMBEDDED_REDIRECT_PARAM | redirect | medium | technical | Query param contains a URL to a different registrable domain |
| URL.SHORTENER | redirect | low | heuristic | Known shortener (always expanded via redirects) |
| URL.KEYWORDS | phishing | low | heuristic | login/verify/kyc/refund/update/secure in host or path |
| REDIRECT.CROSS_DOMAIN | redirect | medium | technical | Final registrable domain ≠ submitted one |
| REDIRECT.LONG_CHAIN | redirect | high | technical | ≥ 3 cross-domain hops |
| DOMAIN.YOUNG | domain | medium | heuristic | RDAP registration < 30 days; for a site on a hosting platform (private PSL suffix), first crt.sh certificate naming it < 30 days |
| DOMAIN.SUSPICIOUS_TLD | domain | low | heuristic | TLD on curated abuse-heavy list |
| DOMAIN.FAST_FLUX | domain | medium | heuristic | ≥ 5 A records across ≥ 3 distinct /16 networks with a TTL ≤ 300 s (DNS-over-HTTPS, dns.google) |
| DOMAIN.FREE_DNS | domain | low | heuristic | Nameservers on a free/dynamic DNS provider, or the host is a dynamic-DNS subdomain |
| PAGE.CREDENTIAL_FORM | phishing | high | technical | Password/OTP/card field on a page whose title/brand text claims a protected brand while the domain isn't official |
| PAGE.FORM_ACTION_CROSS_DOMAIN | phishing | high | technical | Sensitive form posts to a different registrable domain |
| PAGE.BRAND_MISMATCH | impersonation | medium | technical | Title/og:site_name claims a protected brand; domain not official (no credential form) |
| PAGE.LLM_CLAIMED_BRAND | impersonation | medium | heuristic | LLM extracted a claimed brand from page text that is **not** in brands.json and the domain doesn't obviously belong to it (PhishLLM-style). If the brand IS in brands.json, the deterministic PAGE.* checks decide instead. |

### TLS

| check_id | Category | Severity | Strength | Fires when |
|---|---|---|---|---|
| TLS.DISTRUSTED_CA | tls_trust | critical | authoritative | Any presented cert's cert SHA-256 **or SPKI SHA-256** matches `distrusted_cas.json` entries (the 8 eMudhra G3B/G3C intermediates, including Sectigo cross-signed copies of the same keys) |
| TLS.REMOVED_ROOT | tls_trust | high | authoritative | Chain terminates at a root in `removed_roots` (emSign ECC Root CA - G3), without a compromised intermediate |
| TLS.REVOKED | tls_trust | critical | authoritative | OCSP/CRL says revoked |
| TLS.UNTRUSTED_ROOT | tls_trust | high | technical | Chain doesn't validate to the Mozilla root store (certifi) |
| TLS.SELF_SIGNED | tls_trust | high | technical | Leaf is self-signed |
| TLS.EXPIRED | tls_config | high | technical | notAfter < now |
| TLS.NOT_YET_VALID | tls_config | high | technical | notBefore > now |
| TLS.HOSTNAME_MISMATCH | tls_trust | high | technical | Host not covered by SAN |
| TLS.WEAK_KEY | tls_config | high | technical | RSA < 2048 or EC < 256 |
| TLS.WEAK_SIGNATURE | tls_config | high | technical | SHA-1/MD5 signature on leaf or intermediate |
| TLS.NO_HTTPS | phishing | medium | technical | No HTTPS (raised to high if PAGE.CREDENTIAL_FORM) |
| TLS.CT_NOT_LOGGED | tls_trust | medium | technical | No embedded SCTs and not found in Cert Spotter (crt.sh fallback) |
| TLS.CT_UNEXPECTED_ISSUER | tls_trust | medium | heuristic | New cert in last 7 days from a CA never seen for this domain in CT history |
| TLS.CERT_VERY_NEW | tls_trust | low | heuristic | Leaf issued < 7 days ago |
| TLS.INCOMPLETE_CHAIN | tls_config | low | technical | Server omits intermediates (config, not compromise) |

### Message

| check_id | Category | Severity | Strength | Fires when |
|---|---|---|---|---|
| MSG.CREDENTIAL_REQUEST | social_engineering | medium | heuristic | Asks for OTP/password/PIN/CVV/seed phrase (regex + LLM) |
| MSG.PAYMENT_REQUEST | social_engineering | medium | heuristic | Asks to pay, scan a QR, or "receive money" via UPI |
| MSG.URGENCY | social_engineering | low | heuristic | Deadline, threat of block/suspension |
| MSG.AUTHORITY_IMPERSONATION | social_engineering | low | heuristic | Claims to be a bank/gov/university/company, or police/court/RBI/cyber cell |
| MSG.REWARD_LURE | social_engineering | low | heuristic | Prize, cashback, refund, job offer with fee |
| MSG.SCAM_PATTERN | social_engineering | medium | heuristic | Two different pressure tactics (urgency, authority, reward; a prize/guaranteed-return offer counts as two) **and** a way to act on them (link, phone, UPI ID, email, payment/credential request, "reply YES") |
| MSG.SENDER_DOMAIN_MISMATCH | impersonation | high | technical | Email From/Reply-To domain doesn't match the claimed organisation's official domain (headers present) |
| MSG.LINK_TEXT_MISMATCH | phishing | high | technical | Displayed link text domain ≠ actual href domain |
| MSG.DMARC_FAIL | impersonation | high | technical | Pasted headers: the receiving server's top-most `Authentication-Results` says `dmarc=fail` |
| MSG.SPF_DKIM_FAIL | impersonation | medium | technical | Pasted headers: `spf=fail`/`softfail`, DKIM not `pass`, and no DMARC verdict |

Extracted URLs run through the full URL pipeline, and their findings are attached with an `indicator` reference.
Bare domains with no scheme ("update KYC at hdfc-verify.in") count as links when they are lowercase and end in a real
public suffix. A credential or payment phrase straight after a negation ("do not share this OTP") is not a request.
Signal regexes run on redacted text with the placeholders blanked, so a masked number never reads as "OTP".

### Correlation

| check_id | Category | Severity | Strength | Fires when |
|---|---|---|---|---|
| CORR.VALIDATED_MATCH | correlation | critical | authoritative | Shares an indicator with an on-chain report in `Validated` status |
| CORR.PRIOR_REPORTS | correlation | medium | heuristic | Shares indicator(s) with ≥ 2 prior unvalidated reports |
| CORR.SHARED_INFRA | correlation | low | heuristic | Same IP/ASN/nameserver/cert as a prior suspicious report |
| CORR.SIMILAR_MESSAGE | correlation | low | heuristic | Message template (links, numbers, amounts tokenised) ≥ 60% Jaccard (word 3-shingles) with a stored suspicious-or-worse message |

Implementation (`correlation/checks.py`), deliberately conservative so a legitimate site is never dragged down:
only prior reports at `suspicious` or worse count; allowlisted domains and shorteners never correlate; IP, ASN,
nameserver and certificate matches only ever yield CORR.SHARED_INFRA; `VALIDATED_MATCH` needs a specific indicator
(domain, email, phone, UPI ID, crypto address) and a registry row whose status is `validated` as last seen by this
server. Evidence lists matching report IDs and never the matching email, phone, UPI or crypto value.

`PAGE.LLM_CLAIMED_BRAND` (`checks/page_llm.py`, group `page.llm`, weight 0) fires only when the model extracted a
brand that is not in brands.json, the page asks for credentials or payment, the host is not allowlisted and no
word of the brand appears in the registrable domain. The model extracts; code decides.

### Security posture (reported separately, 0 points)

`POSTURE.NO_HSTS, POSTURE.NO_CSP, POSTURE.NO_XFO, POSTURE.NO_XCTO, POSTURE.MIXED_CONTENT, POSTURE.OLD_TLS_VERSION,
POSTURE.SERVER_BANNER_VERSION, POSTURE.OUTDATED_SOFTWARE, POSTURE.NO_SPF, POSTURE.NO_DMARC, POSTURE.DMARC_NOT_ENFORCED, POSTURE.EXPOSED_FILE` (only `/.git/HEAD`, `/.env` via a single HEAD/GET, and
only for a site whose owner has proven control of the domain, see `app/ownership.py`).

`POSTURE.OUTDATED_SOFTWARE` compares the `Server` / `X-Powered-By` version (nginx, Apache httpd, PHP, OpenSSL, Tomcat) with an end-of-life snapshot from endoflife.date (`data/eol_software.json`). Only a release line past end of life fires; an old patch level inside a supported line does not, because distributions backport fixes.

Posture checks run as group `posture.headers` (coverage weight 0, so they never change coverage or the score).
The `severity` on a POSTURE finding is a display hint only (low for a missing defence, info for observations).
`POSTURE.EXPOSED_FILE` runs only when `POST /assess` carries `owns_site: true` **and** an `ownership_token` for the
site's registrable domain (two GETs through safe_fetch, no file contents kept). Without a valid grant the request is
refused with 403. The probe also keeps its own limit of 3 requests per minute per IP.

## 7. LLM boundaries

- Allowed LLM jobs: (a) extract the claimed brand and whether the page/message seeks credentials or payment,
  (b) language signals, (c) the explanation. The deterministic code decides what each extraction means.

- Input: the report's findings (as JSON) plus redacted untrusted text inside `<untrusted_input>`.
- Output schema: `summary`, `language_signals[]` (each mapped to a MSG.* check_id), `verified_evidence_refs[]`.
- Any `check_id` that isn't in the report is dropped. Any signal it emits is forced to `heuristic`.
- Instructions found inside `<untrusted_input>` are ignored, and the summary notes "this content contained
  instructions directed at automated systems" (a nice demo moment).
