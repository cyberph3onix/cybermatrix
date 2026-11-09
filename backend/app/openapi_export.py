"""Write the OpenAPI schema for frontend type generation: `uv run python -m app.openapi_export ../frontend/lib/openapi.json`."""
from __future__ import annotations

import json
import sys

from app.main import app


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "-"
    text = json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n"
    if out == "-":
        sys.stdout.write(text)
    else:
        with open(out, "w") as f:
            f.write(text)


if __name__ == "__main__":
    main()
