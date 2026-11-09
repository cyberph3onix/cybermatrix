"""URL.LOOKALIKE.* checks.

HOMOGLYPH: UTS#39 confusable skeleton equals a brand label. TYPOSQUAT: (1) dnstwist permutation set precomputed
at startup, then (2) edit distance and brand+affix. Labels shorter than the brand's min_typo_len only match as homoglyphs (dnstwist `homoglyph`
fuzzer or skeleton), exactly on another suffix, or with an affix; never by edit distance or other fuzzers.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
import time
import unicodedata
from dataclasses import dataclass
from functools import cache

import dnstwist

from app.brands import DATA_DIR, Brand, BrandIndex, get_index
from app.checks.base import AssessmentContext, CheckResult, evidence, make_finding, make_run
from app.schemas import CheckStatus, Finding
from app.urlutil import ParsedURL, registrable_domain, split_domain, to_unicode_host

SOURCE = "local:lookalike"
GROUP = "url.lookalike"
TLD_SWAP = ["com", "in", "co.in", "net", "org", "info", "xyz", "top", "online", "site", "app", "live", "shop"]
HOMOGLYPH_FUZZERS = frozenset({"homoglyph", "cyrillic"})
AFFIXES = frozenset({
    "kyc", "verify", "verification", "login", "signin", "secure", "update", "online", "net", "netbanking",
    "bank", "banking", "support", "help", "care", "reward", "rewards", "refund", "pay", "app", "india", "in",
    "official", "service", "services", "alert", "auth", "account", "customer", "offer", "offers", "cashback",
    "gift", "kycupdate", "portal", "web", "my", "e", "go", "get", "claim", "bonus", "points", "redeem",
})


@dataclass(frozen=True)
class _Hit:
    brand_id: str
    target: str
    fuzzer: str


# ---------------- (1) dnstwist ----------------

CACHE_DIR = DATA_DIR / ".cache"


def _cache_key() -> str:
    h = hashlib.sha256((DATA_DIR / "brands.json").read_bytes())
    h.update(json.dumps([getattr(dnstwist, "__version__", "?"), TLD_SWAP, sorted(AFFIXES)]).encode())
    return h.hexdigest()[:16]


@cache
def permutation_index() -> dict[str, _Hit]:
    """registrable-domain permutation → hit. Built once at startup (cached on disk: dnstwist takes ~5 s)."""
    path = CACHE_DIR / f"permutations-{_cache_key()}.json.gz"
    try:
        raw = json.loads(gzip.decompress(path.read_bytes()))
        return {k: _Hit(*v) for k, v in raw.items()}
    except (OSError, ValueError):
        pass
    out = _build_permutations()
    try:
        CACHE_DIR.mkdir(exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(gzip.compress(json.dumps({k: [h.brand_id, h.target, h.fuzzer] for k, h in out.items()})
                                      .encode()))
        tmp.replace(path)
    except OSError:
        pass
    return out


def _build_permutations() -> dict[str, _Hit]:
    """Short labels (below min_typo_len) keep dnstwist homoglyph-fuzzer hits only."""
    idx = get_index()
    official = set(idx.official)
    out: dict[str, _Hit] = {}
    for b in idx.brands:
        for d in b.official_domains:
            _, label, _ = split_domain(d)
            short = len(label) < b.min_typo_len
            fz = dnstwist.Fuzzer(d, tld_dictionary=TLD_SWAP)
            fz.generate()
            for p in fz.domains:
                name, kind = p["domain"].lower(), p["fuzzer"]
                if kind.startswith("*") or name in official:
                    continue
                if short and kind not in HOMOGLYPH_FUZZERS:
                    continue
                out.setdefault(name, _Hit(b.id, d, kind))
    return out


# ---------------- (2) UTS#39 skeleton ----------------

@cache
def _confusables() -> dict[str, str]:
    table: dict[str, str] = {}
    for line in (DATA_DIR / "confusables.txt").read_text(encoding="utf-8-sig").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        src, tgt, *_ = (f.strip() for f in line.split(";"))
        table["".join(chr(int(c, 16)) for c in src.split())] = "".join(chr(int(c, 16)) for c in tgt.split())
    return table


def skeleton(s: str) -> str:
    """UTS#39 skeleton: NFD, map each confusable to its prototype, NFD again."""
    tbl = _confusables()
    s = unicodedata.normalize("NFD", s)
    mapped = "".join(tbl.get(ch, ch) for ch in s)
    return unicodedata.normalize("NFD", mapped)


def _skel(s: str) -> str:
    return skeleton(s).casefold()


# ---------------- (3) edit distance ----------------

def osa_distance(a: str, b: str) -> int:
    """Optimal-string-alignment Damerau-Levenshtein distance."""
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def _max_distance(brand_label: str) -> int:
    # Two edits on an 8-letter label is a quarter of it changed: oneindia.in sat 2 edits from "pnbindia".
    return 1 if len(brand_label) <= 8 else 2


def _affixed(label: str, brand_label: str) -> bool:
    parts = [p for p in re.split(r"[-_0-9]+", label) if p]
    if len(parts) > 1 and brand_label in parts:
        return True
    for p in parts or [label]:
        if p == brand_label:
            continue
        if p.startswith(brand_label) and p[len(brand_label):] in AFFIXES:
            return True
        if p.endswith(brand_label) and p[: -len(brand_label)] in AFFIXES:
            return True
        if len(brand_label) >= 6 and brand_label in p:
            return True
    return False


# ---------------- analysis ----------------

def analyze(u: ParsedURL, idx: BrandIndex) -> list[Finding]:
    if u.ip is not None:
        return []
    reg = registrable_domain(u.host)
    if reg in idx.official:
        return []
    url = u.url_without_userinfo()
    by_id = {b.id: b for b in idx.brands}
    _, label_ascii, _ = split_domain(u.host)
    label_u = to_unicode_host(label_ascii).lower()

    homoglyph: tuple[Brand, str, str] | None = None
    typo: tuple[Brand, str, str] | None = None

    # HOMOGLYPH means "renders the same": UTS#39 skeleton equality (case-folded) with a brand label.
    sk = _skel(label_u)
    for b in idx.brands:
        for lbl in b.labels:
            if label_u != lbl and sk == _skel(lbl):
                homoglyph = (b, lbl, "uts39_skeleton")
                break
        if homoglyph:
            break

    # dnstwist permutations are near-misses (its loose `homoglyph` fuzzer includes n/m-style swaps), so a
    # dnstwist hit without skeleton equality is a TYPOSQUAT.
    hit = permutation_index().get(reg)
    if hit and homoglyph is None:
        typo = (by_id[hit.brand_id], hit.target, f"dnstwist:{hit.fuzzer}")

    if typo is None and homoglyph is None:
        typo = _typo(label_u, idx)

    out: list[Finding] = []
    if homoglyph:
        b, target, how = homoglyph
        out.append(make_finding(
            "URL.LOOKALIKE.HOMOGLYPH", f"Domain is visually identical to {b.name}'s",
            [evidence("url_component", f"'{to_unicode_host(u.host)}' renders like '{target}' ({how})", SOURCE,
                      {"url": url, "brand": b.name, "lookalike_of": target, "method": how,
                       "ascii_host": u.host})],
            f"The address is built from look-alike characters to pass as {b.name}.",
            f"Do not trust this link. Open {b.name}'s site by typing {b.official_domains[0]}."))
    if typo:
        b, target, how = typo
        out.append(make_finding(
            "URL.LOOKALIKE.TYPOSQUAT", f"Domain closely resembles {b.name}'s",
            [evidence("url_component", f"'{reg}' is a near-miss of '{target}' ({how})", SOURCE,
                      {"url": url, "brand": b.name, "lookalike_of": target, "method": how})],
            f"Typo or affix variants of {b.name}'s domain are commonly registered for phishing.",
            f"The official address is {b.official_domains[0]}."))
    return out


_LEET = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "1": "l"})
_LEET_I = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "1": "i"})


def _deleet(label: str) -> list[str]:
    """Readings of a label with digits swapped back to the letters they imitate (paypa1 -> paypal / paypai)."""
    if not any(c.isdigit() for c in label):
        return []
    return list(dict.fromkeys(v for v in (label.translate(_LEET), label.translate(_LEET_I)) if v != label))


def _typo(label: str, idx: BrandIndex) -> tuple[Brand, str, str] | None:
    parts = [p for p in re.split(r"[-_]+", label) if p] or [label]
    for b in idx.brands:
        for lbl in b.labels:
            if label == lbl:
                return b, lbl, "same_label_other_suffix"
            if _affixed(label, lbl):
                return b, lbl, "brand_plus_affix"
            for v in _deleet(label):  # digit-for-letter swap: paypa1-secure-login, amaz0n-offers
                if v == lbl and len(lbl) >= b.min_typo_len:  # short brand names never match by lookalike alone
                    return b, lbl, "digit_substitution"
                if _affixed(v, lbl):
                    return b, lbl, "digit_substitution+affix"
            if len(lbl) < b.min_typo_len:
                continue
            for p in parts:
                if len(p) < b.min_typo_len:
                    continue
                dist = osa_distance(p, lbl)
                if 0 < dist <= _max_distance(lbl):
                    return b, lbl, f"edit_distance:{dist}"
    return None


async def run(ctx: AssessmentContext, url: ParsedURL | None = None) -> CheckResult:
    t0 = time.monotonic()
    try:
        findings = analyze(url or ctx.url, ctx.brands)
    except Exception as e:  # noqa: BLE001
        return make_run(GROUP, CheckStatus.FAILED, SOURCE, t0, f"error: {type(e).__name__}"), []
    return make_run(GROUP, CheckStatus.COMPLETED, SOURCE, t0), findings
