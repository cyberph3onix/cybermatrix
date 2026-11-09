"""Coverage per docs/RISK_ENGINE.md §4."""
from __future__ import annotations

from app.schemas import CheckRun, CheckStatus, Coverage

# URL assessment weights. Table groups that cover several check runs are split so the group total matches the doc:
# url.structure + lookalike = 10, tls.chain + tls.revocation + tls.ct = 20.
WEIGHTS: dict[str, int] = {
    "url.structure": 5,
    "url.lookalike": 5,
    "intel.gsb": 10,
    "intel.urlhaus": 10,
    "intel.openphish": 10,
    "intel.virustotal": 10,
    "fetch.redirects": 15,
    "page.content": 10,
    "tls.chain": 10,
    "tls.revocation": 5,
    "tls.ct": 5,
    "domain.rdap": 3,  # domain.rdap + domain.dns = 5
    "domain.dns": 2,
}


def weight(group: str) -> int:
    return WEIGHTS.get(group, 0)


def compute(check_runs: list[CheckRun]) -> Coverage:
    """Coverage = completed weight / applicable weight. Skipped runs are not applicable.

    If a group appears more than once (e.g. a re-run on the final URL) its best status counts once.
    """
    rank = {CheckStatus.COMPLETED.value: 0, CheckStatus.FAILED.value: 1,
            CheckStatus.UNAVAILABLE.value: 2, CheckStatus.SKIPPED.value: 3}
    best: dict[str, CheckRun] = {}
    for r in check_runs:
        cur = best.get(r.check_group)
        if cur is None or rank[_s(r.status)] < rank[_s(cur.status)]:
            best[r.check_group] = r
    buckets: dict[str, list[str]] = {k: [] for k in rank}
    applicable = done = 0
    for g, r in best.items():
        st = _s(r.status)
        buckets[st].append(g)
        if st == CheckStatus.SKIPPED.value:
            continue
        applicable += r.weight
        if st == CheckStatus.COMPLETED.value:
            done += r.weight
    pct = (done * 100) // applicable if applicable else 0
    return Coverage(
        percent=pct,
        completed=sorted(buckets["completed"]),
        unavailable=sorted(buckets["unavailable"]),
        failed=sorted(buckets["failed"]),
        skipped=sorted(buckets["skipped"]),
    )


def _s(v: object) -> str:
    return v.value if isinstance(v, CheckStatus) else str(v)
