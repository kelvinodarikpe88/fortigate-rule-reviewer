"""Demo without a server: python -m app.cli fixtures/planted.conf"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from . import llm
from .fortigate import review

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else FIXTURES / "planted.conf"
    result = review(path.read_text())
    rule_ids = {str(n) for n in range(1, result["summary"]["rules"] + 1)}
    for finding in result["findings"]:
        note = llm.build_change_request(finding, rule_ids)
        finding["change_request"] = note["text"]
        finding["change_request_source"] = note["source"]
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
