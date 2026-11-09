"""Message-analysis evaluation on a hand-verified sample (eval/data/scamshield_sample.json).

    cd backend && uv run python -m eval.scamshield            # deterministic only (offline, repeatable)
    cd backend && uv run python -m eval.scamshield --llm      # also LLM language signals (needs GEMINI_API_KEY)
    cd backend && uv run python -m eval.scamshield --markdown # table for docs/TESTING.md
    cd backend && uv run python -m eval.scamshield --corpus sms_fraud_classification.json  # held-out: every other
        labelled row of the full dataset (download it from huggingface.co/datasets/haxrits/ScamShield-IN; not committed)

Links found in a message go through the URL checks that need no network (structure + lookalike); page fetch, TLS,
threat intel and RDAP are left out so the numbers do not depend on which scam sites are still online.
"flagged" means suspicious or worse. A legitimate message that is low_risk or inconclusive counts as not flagged:
inconclusive is the honest answer when the AI step is off, and it never tells the user something is fraud.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from collections import Counter
from pathlib import Path

from app.checks import lookalike, url_structure
from app.pipeline import CheckSpec, Deps
from app.pipeline_message import assess_message
from app.schemas import CheckStatus

DATA = Path(__file__).resolve().parent / "data" / "scamshield_sample.json"
FLAGGED = {"suspicious", "high_risk", "confirmed_malicious"}


def offline_deps() -> Deps:
    return Deps(checks=[CheckSpec("url.structure", url_structure.run, 5, url_structure.SOURCE),
                        CheckSpec("url.lookalike", lookalike.run, 5, lookalike.SOURCE)])


def load(corpus: Path | None) -> list[dict]:
    sample = json.loads(DATA.read_text())["messages"]
    if corpus is None:
        return sample
    seen = {m["message"] for m in sample}
    return [{"id": f"corpus-{i}", "label": r["label"], "fraud_type": r.get("fraud_type"), "message": r["message"],
             "source": "ScamShield-IN"}
            for i, r in enumerate(json.loads(corpus.read_text()))
            if r.get("label") in ("fraud", "legit") and r["message"] not in seen]


def by_type(rows: list[dict]) -> dict[str, str]:
    out: dict[str, list[int]] = {}
    for r in rows:
        if r["label"] == "fraud":
            t = out.setdefault(r["fraud_type"] or "?", [0, 0])
            t[0] += r["flagged"]
            t[1] += 1
    return {k: f"{a}/{n}" for k, (a, n) in sorted(out.items())}


async def evaluate(use_llm: bool = False, corpus: Path | None = None, pace: float = 0) -> list[dict]:
    llm = None
    if use_llm:
        from app.ai.llm import default_llm
        llm = default_llm()
        if llm is None:
            raise SystemExit("--llm needs GEMINI_API_KEY or ANTHROPIC_API_KEY")
    deps, out = offline_deps(), []
    for m in load(corpus):
        r = await assess_message(m["message"], deps=deps, llm=llm)
        cls = str(getattr(r.classification, "value", r.classification))
        sig = next((c for c in r.check_runs if c.check_group == "message.signals"), None)
        out.append({**m, "classification": cls, "flagged": cls in FLAGGED, "coverage": r.coverage.percent,
                    "checks": sorted({f.check_id for f in r.findings}),
                    "llm_ok": sig is not None and sig.status == CheckStatus.COMPLETED})
        if llm is not None and pace:
            await asyncio.sleep(pace)  # free-tier requests-per-minute limits
    return out


def summary(rows: list[dict]) -> dict:
    tp = sum(r["flagged"] for r in rows if r["label"] == "fraud")
    fn = sum(not r["flagged"] for r in rows if r["label"] == "fraud")
    fp = sum(r["flagged"] for r in rows if r["label"] == "legit")
    tn = sum(not r["flagged"] for r in rows if r["label"] == "legit")
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "llm_ok": sum(r["llm_ok"] for r in rows), "n": len(rows),
            "precision": round(100 * tp / (tp + fp)) if tp + fp else 0,
            "recall": round(100 * tp / (tp + fn)) if tp + fn else 0,
            "by_class": {lab: dict(Counter(r["classification"] for r in rows if r["label"] == lab))
                         for lab in ("fraud", "legit")}}


def markdown(rows: list[dict], s: dict) -> str:
    lines = ["| | flagged | not flagged |", "|---|---|---|",
             f"| fraud ({s['tp'] + s['fn']}) | {s['tp']} | {s['fn']} |",
             f"| legit ({s['fp'] + s['tn']}) | {s['fp']} | {s['tn']} |", "",
             f"Precision {s['precision']}%, recall {s['recall']}%. "
             f"LLM signals completed on {s['llm_ok']}/{s['n']} messages.", "",
             "| Label | Class | Count |", "|---|---|---|"]
    for lab, c in s["by_class"].items():
        lines += [f"| {lab} | `{k}` | {v} |" for k, v in sorted(c.items())]
    missed = [r for r in rows if r["label"] == "fraud" and not r["flagged"]]
    wrong = [r for r in rows if r["label"] == "legit" and r["flagged"]]
    for title, rs in (("Missed fraud", missed), ("Legitimate but flagged", wrong)):
        if rs:
            lines += ["", f"{title}:", ""] + [f"- `{r['id']}` ({r['fraud_type'] or 'legit'}): {r['message'][:110]}… → "
                                              f"`{r['classification']}` {', '.join(r['checks']) or 'no findings'}"
                                              for r in rs]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", action="store_true")
    ap.add_argument("--markdown", action="store_true")
    ap.add_argument("--pace", type=float, default=4.0, help="seconds between LLM messages (free-tier RPM)")
    ap.add_argument("--corpus", type=Path, help="full dataset JSON: evaluate every labelled row not in the sample")
    a = ap.parse_args()
    rows = asyncio.run(evaluate(a.llm, a.corpus, a.pace))
    s = summary(rows) | {"fraud_flagged_by_type": by_type(rows)}
    if a.markdown:
        print(markdown(rows, s))
        return
    for r in rows:
        mark = "ok " if r["flagged"] == (r["label"] == "fraud") else "XX "
        print(f"{mark}{r['id']:14} {r['label']:5} {r['classification']:20} {','.join(r['checks'])[:80]}")
    print(json.dumps(s, indent=1))


if __name__ == "__main__":
    main()
