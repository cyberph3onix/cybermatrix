"""Protected brands, allowlists and curated host lists, loaded once."""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

from app.urlutil import registrable_domain

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Brand:
    id: str
    name: str
    official_domains: tuple[str, ...]
    labels: tuple[str, ...]
    aliases: tuple[str, ...]
    min_typo_len: int


@dataclass
class BrandIndex:
    brands: list[Brand]
    tranco: frozenset[str]
    abusable: tuple[tuple[str, str], ...]  # (host suffix, path prefix)
    shorteners: frozenset[str]
    suspicious_tlds: frozenset[str]
    tranco_loaded: bool = True
    official: dict[str, Brand] = field(default_factory=dict)
    by_label: dict[str, Brand] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for b in self.brands:
            for d in b.official_domains:
                self.official.setdefault(d, b)
            for lbl in b.labels:
                self.by_label.setdefault(lbl, b)
        self._alias_res = [(b, _alias_regex(a)) for b in self.brands for a in b.aliases]

    # ---- host classification ----
    def is_abusable(self, host: str, path: str = "/") -> bool:
        h = host.lower().rstrip(".")
        p = path or "/"
        for suffix, prefix in self.abusable:
            if (h == suffix or h.endswith("." + suffix)) and (not prefix or p.startswith(prefix)):
                return True
        return False

    def official_brand(self, host: str, path: str = "/") -> Brand | None:
        """Brand whose official domain this host is on. Abusable hosts (sites.google.com) are never official."""
        if self.is_abusable(host, path):
            return None
        return self.official.get(registrable_domain(host))

    def in_tranco(self, host: str) -> bool:
        return registrable_domain(host) in self.tranco

    def allowlisted(self, host: str, path: str = "/") -> bool:
        """Official or Tranco top 10k, and not an abusable host. Gates false-positive dampening."""
        if self.is_abusable(host, path):
            return False
        return self.official_brand(host, path) is not None or self.in_tranco(host)

    def is_shortener(self, host: str) -> bool:
        return host.lower() in self.shorteners or registrable_domain(host) in self.shorteners

    # ---- text ----
    def brands_claimed_in(self, text: str) -> list[tuple[Brand, str]]:
        out: list[tuple[Brand, str]] = []
        seen: set[str] = set()
        for b, rx in self._alias_res:
            m = rx.search(text)
            if m and b.id not in seen:
                seen.add(b.id)
                out.append((b, m.group(0)))
        return out


def _alias_regex(alias: str) -> re.Pattern[str]:
    # Short all-caps acronyms (SBI, PNB, IEM) are case-sensitive so ordinary words don't match.
    flags = 0 if (alias.isupper() and len(alias) <= 5) else re.IGNORECASE
    return re.compile(r"(?<![\w.])" + re.escape(alias) + r"(?![\w])", flags)


def _lines(name: str) -> list[str]:
    p = DATA_DIR / name
    if not p.exists():
        return []
    return [ln.strip().lower() for ln in p.read_text().splitlines() if ln.strip() and not ln.startswith("#")]


def load_index(data_dir: Path | None = None) -> BrandIndex:
    d = data_dir or DATA_DIR
    raw = json.loads((d / "brands.json").read_text())
    default_min = int(raw.get("default_min_typo_len", 5))
    brands = [
        Brand(id=b["id"], name=b["name"], official_domains=tuple(b["official_domains"]),
              labels=tuple(lbl.lower() for lbl in b["labels"]), aliases=tuple(b["aliases"]),
              min_typo_len=int(b.get("min_typo_len", default_min)))
        for b in raw["brands"]
    ]
    tranco_path = d / "tranco_top10k.csv"
    tranco: set[str] = set()
    if tranco_path.exists():
        for ln in tranco_path.read_text().splitlines():
            dom = ln.split(",", 1)[-1].strip().lower()
            if dom:
                tranco.add(dom)
    else:
        log.warning("tranco_top10k.csv missing; allowlist dampening limited to official brand domains")
    abusable = []
    for entry in _lines("abusable_hosts.txt"):
        host, _, path = entry.partition("/")
        abusable.append((host, "/" + path if path else ""))
    return BrandIndex(
        brands=brands,
        tranco=frozenset(tranco),
        abusable=tuple(abusable),
        shorteners=frozenset(_lines("shorteners.txt")),
        suspicious_tlds=frozenset(_lines("suspicious_tlds.txt")),
        tranco_loaded=tranco_path.exists(),
    )


@cache
def get_index() -> BrandIndex:
    return load_index()
