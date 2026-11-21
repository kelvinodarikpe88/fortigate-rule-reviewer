from pathlib import Path

from app.fortigate import covers, parse_policies, review, superset

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def planted() -> str:
    return (FIXTURES / "planted.conf").read_text()


def clean() -> str:
    return (FIXTURES / "clean.conf").read_text()


def categories(result) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for finding in result["findings"]:
        out.setdefault(finding["category"], []).append(finding["rule_id"])
    return out


def test_parses_every_policy():
    rules = parse_policies(planted())
    assert len(rules) == 9
    assert rules[1].name == "any-any-out"


def test_planted_config_finds_nine_distinct_issues():
    result = review(planted())
    assert result["summary"]["findings"] == 9
    found = categories(result)
    assert set(found) == {
        "any_any",
        "management_exposed",
        "shadowed",
        "undefined_object",
        "no_logging",
        "temporary_no_expiry",
        "broad_destination",
        "dead_deny",
        "duplicate",
    }
    assert all(len(ids) == 1 for ids in found.values())


def test_clean_config_is_clean():
    assert review(clean())["summary"]["findings"] == 0


def test_inbound_web_is_not_management_exposure():
    found = categories(review(planted()))
    assert found["management_exposed"] == ["3"]


def test_shadowed_rule_is_not_also_reported_as_broad():
    found = categories(review(planted()))
    assert found["shadowed"] == ["5"]
    assert found["broad_destination"] == ["9"]


def test_duplicate_wins_over_shadowed_for_the_same_rule():
    found = categories(review(planted()))
    assert found["duplicate"] == ["7"]
    assert "7" not in found["shadowed"]


def test_vendor_rule_without_expiry_is_flagged():
    assert categories(review(planted()))["temporary_no_expiry"] == ["4"]


def test_undefined_object_is_not_reported_for_builtin_services():
    found = categories(review(planted()))
    assert found["undefined_object"] == ["8"]


def test_dead_deny_points_at_the_rule_that_makes_it_unreachable():
    result = review(planted())
    dead = next(f for f in result["findings"] if f["category"] == "dead_deny")
    assert dead["rule_id"] == "6"
    assert "rule 2" in dead["evidence"]


def test_findings_are_ordered_by_severity_then_rule():
    severities = [f["severity"] for f in review(planted())["findings"]]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert severities == sorted(severities, key=lambda s: order[s])


def test_review_is_reproducible():
    assert review(planted()) == review(planted())


def test_superset_handles_any_and_case():
    assert superset({"all"}, {"web-server"})
    assert superset({"ALL"}, {"HTTPS"})
    assert superset({"HTTPS", "HTTP"}, {"HTTPS"})
    assert not superset({"HTTPS"}, {"HTTP"})


def test_covers_requires_an_accept_rule():
    rules = parse_policies(planted())
    deny = next(r for r in rules if r.rule_id == "6")
    later_http = next(r for r in rules if r.rule_id == "5")
    assert not covers(deny, later_http)
