import re
from pathlib import Path

from app.checks.catalogue import CATALOGUE

DOC = Path(__file__).resolve().parents[2] / "docs" / "RISK_ENGINE.md"


def test_catalogue_matches_risk_engine_doc():
    rows = {}
    for line in DOC.read_text().splitlines():
        m = re.match(r"\| ([A-Z]+\.[A-Z0-9_.]+) \| (\w+) \| (\w+) \| (\w+) \|", line)
        if m:
            rows[m.group(1)] = (m.group(2), m.group(3), m.group(4))
    assert rows == {k: tuple(v) for k, v in CATALOGUE.items()}
