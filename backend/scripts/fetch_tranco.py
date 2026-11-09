"""One-off: download the Tranco top-1M list and keep the top 10k registrable domains in data/tranco_top10k.csv.

Usage: uv run python scripts/fetch_tranco.py
"""
from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

import httpx

OUT = Path(__file__).resolve().parents[1] / "data" / "tranco_top10k.csv"
URL = "https://tranco-list.eu/top-1m.csv.zip"


def main() -> int:
    r = httpx.get(URL, timeout=60, follow_redirects=True)
    r.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        name = z.namelist()[0]
        lines = z.read(name).decode().splitlines()[:10_000]
    OUT.write_text("\n".join(lines) + "\n")
    print(f"wrote {len(lines)} rows to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
