"""The README makes claims. This test is what makes them true."""
import re
from pathlib import Path

from app.fortigate import review

ROOT = Path(__file__).resolve().parent.parent
CLAIM_RE = re.compile(r"<!--\s*claims:\s*(.*?)\s*-->")


def claims() -> dict[str, int]:
    match = CLAIM_RE.search((ROOT / "README.md").read_text())
    assert match, "README.md must carry a <!-- claims: ... --> marker"
    return {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", match.group(1))}


def test_readme_numbers_match_the_fixtures():
    planted = review((ROOT / "fixtures" / "planted.conf").read_text())
    clean = review((ROOT / "fixtures" / "clean.conf").read_text())
    actual = {
        "rules": planted["summary"]["rules"],
        "findings": planted["summary"]["findings"],
        "critical": planted["summary"]["by_severity"]["critical"],
        "clean": clean["summary"]["findings"],
    }
    for key, value in claims().items():
        assert actual[key] == value, f"README claims {key}={value}, evidence says {actual[key]}"
