"""Live demo / brief test cases against a running API (docker compose stack).

    cd backend && uv run python -m demo.live                       # demo run, prints a table
    cd backend && uv run python -m demo.live --record ../docs/evidence/test_runs.json

Inputs are the brief's cases. Nothing here is a live phishing site: the "suspicious" links are Google's official
Safe Browsing test pages, an invented lookalike name that does not resolve, and badssl.com's expired certificate.
Recorded-fixture reports (demo.seed: eMudhra chain, PayPal-lookalike kit) are listed too; they are the fallback when
an external API is down, because they need no network. Observed results are written as-is.
"""
from __future__ import annotations

import argparse
import json
import sys
import time

import httpx

API = "http://localhost:8000"
GSB_PHISH = "https://testsafebrowsing.appspot.com/s/phishing.html"

# (id, group, expected, input, what it demonstrates)
CASES = [
    ("S1-message", "suspicious", "suspicious_or_worse",
     "URGENT: Dear SBI customer, your YONO account will be blocked today. Update your KYC at "
     f"{GSB_PHISH} or call +91 98765 43210.", "scam SMS: bank impersonation + urgency + listed link"),
    ("S2-tls", "suspicious", "suspicious_or_worse", "https://expired.badssl.com/",
     "TLS: expired certificate (badssl.com test host)"),
    ("S3-lookalike", "suspicious", "suspicious_or_worse", "https://sbi-yono-kyc-verify.top/login",
     "lookalike of SBI on an abuse-heavy TLD (invented name, does not resolve)"),
    ("S4-threat-intel", "suspicious", "suspicious_or_worse", GSB_PHISH,
     "Google's official Safe Browsing phishing test page"),
    ("B1-bank", "benign", "not_flagged", "https://www.sbi.co.in/", "Indian bank (SBI)"),
    ("B2-gov", "benign", "not_flagged", "https://www.incometax.gov.in/iec/foportal/", "Income Tax e-filing portal"),
    ("B3-university", "benign", "not_flagged", "https://wbjeeb.nic.in/", "WBJEE board (admission / exam portal)"),
    ("B4-otp-sms", "benign", "not_flagged",
     "482913 is your OTP for txn of INR 1,250.00 at AMAZON on HDFC Bank card xx1234. Valid for 5 mins. "
     "Do not share this OTP with anyone. -HDFC Bank", "genuine-format bank OTP SMS"),
]
FLAGGED = {"suspicious", "high_risk", "confirmed_malicious"}


def run_case(c: httpx.Client, case) -> dict:
    cid, group, expected, text, what = case
    t0 = time.monotonic()
    try:
        r = c.post(f"{API}/assess", json={"input": text}, timeout=120)
        r.raise_for_status()
        rid = r.json()["report_id"]
        rep = c.get(f"{API}/reports/{rid}").json()
        h = c.get(f"{API}/reports/{rid}/evidence").json()["report_hash"]
    except (httpx.HTTPError, KeyError, ValueError) as e:
        return {"id": cid, "group": group, "input_kind": what, "error": f"{type(e).__name__}: {e}"[:200],
                "seconds": round(time.monotonic() - t0, 1)}
    unavailable = [x["check_group"] for x in rep["check_runs"] if x["status"] in ("unavailable", "failed")]
    flagged = rep["classification"] in FLAGGED
    return {
        "id": cid, "group": group, "what": what, "input": text if group == "benign" or "http" in text[:5] else rep["subject"],
        "report_id": rid, "created_at": rep["created_at"], "classification": rep["classification"],
        "score": rep["score"], "rule": rep["classification_reason"], "coverage": rep["coverage"]["percent"],
        "confidence": rep["confidence"], "report_hash": h,
        "check_ids": sorted({f["check_id"] for f in rep["findings"]}), "unavailable": unavailable,
        "expected": expected, "outcome": ("correct" if flagged == (expected == "suspicious_or_worse") else
                                          ("false_positive" if flagged else "false_negative")),
        "seconds": round(time.monotonic() - t0, 1),
    }


def fixture_reports(c: httpx.Client) -> list[dict]:
    """Seeded recorded-fixture reports already in the DB (python -m demo.seed). No network needed."""
    out = []
    for f in c.get(f"{API}/clusters", timeout=30).json():
        out += f["report_ids"]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", help="write observed results to this JSON file")
    args = ap.parse_args()
    t0 = time.monotonic()
    with httpx.Client() as c:
        try:
            c.get(f"{API}/health", timeout=5).raise_for_status()
        except httpx.HTTPError:
            print("API not reachable at", API, "- start it with: docker compose up -d", file=sys.stderr)
            return 2
        rows = [run_case(c, case) for case in CASES]
    for r in rows:
        if "error" in r:
            print(f"{r['id']:16} ERROR {r['error']}  -> use the fixture report for this case (demo.seed)")
            continue
        gap = f" unavailable={','.join(r['unavailable'])}" if r["unavailable"] else ""
        print(f"{r['id']:16} {r['classification']:20} score {r['score']:3} cov {r['coverage']:3}% "
              f"{r['confidence']:6} {r['outcome']:14} {r['seconds']:5}s  /report/{r['report_id']}{gap}")
    degraded = [r["id"] for r in rows if "error" in r or any(u.startswith("intel.") for u in r.get("unavailable", []))]
    if degraded:
        print("\nSome external sources were unavailable for:", ", ".join(degraded))
        print("Fallback: show the recorded-fixture reports from `python -m demo.seed` (same checks, no network).")
    print(f"\nTotal {time.monotonic() - t0:.1f}s")
    if args.record:
        with open(args.record, "w") as fh:
            json.dump({"note": "Observed results, not edited. Produced by backend/demo/live.py against a fresh "
                               "database (docker compose), real API keys.", "cases": rows}, fh, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
