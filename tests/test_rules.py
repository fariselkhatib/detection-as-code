"""The CI gate. A rule merges only if it is valid, fires on every true-positive event,
stays quiet on every false-positive event, converts to every target SIEM, and the
generated docs are current."""
import json
from pathlib import Path

import pytest

from dac import convert, coverage
from dac.engine import SigmaError, load_rules, Rule
from dac.validate import validate_all

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
RULES = load_rules(ROOT / "rules")


def fixture(rule):
    return json.loads((FIXTURES / f"{rule.path.stem}.json").read_text())


def test_rules_found():
    assert len(RULES) >= 10


def test_all_rules_valid():
    assert validate_all(RULES, FIXTURES) == []


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.path.stem)
def test_fires_on_true_positives(rule):
    events = fixture(rule)["tp"]
    assert events, "need at least one true-positive event"
    for i, ev in enumerate(events):
        assert rule.matches(ev), f"missed TP #{i}: {ev}"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.path.stem)
def test_quiet_on_false_positives(rule):
    events = fixture(rule)["fp"]
    assert events, "need at least one false-positive event"
    for i, ev in enumerate(events):
        assert not rule.matches(ev), f"fired on FP #{i}: {ev}"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.path.stem)
def test_converts_to_all_targets(rule):
    results = convert.convert_rule(rule.path)
    assert results and all(q.strip() for _, _, q in results)


def test_no_orphan_fixtures():
    stems = {r.path.stem for r in RULES}
    assert {p.stem for p in FIXTURES.glob("*.json")} <= stems


def test_generated_docs_current():
    assert convert.main(["--check"]) == 0
    assert coverage.main(["--check"]) == 0


# --- engine unit tests ----------------------------------------------------

def make(detection):
    return Rule(Path("x.yml"), {"detection": detection})


def test_engine_case_insensitive_and_lists():
    r = make({"sel": {"Image|endswith": ["\\a.exe", "\\b.exe"]}, "condition": "sel"})
    assert r.matches({"Image": "C:\\X\\B.EXE"})
    assert not r.matches({"Image": "C:\\X\\c.exe"})


def test_engine_all_modifier():
    r = make({"sel": {"CommandLine|contains|all": ["foo", "bar"]}, "condition": "sel"})
    assert r.matches({"CommandLine": "x foo y bar"})
    assert not r.matches({"CommandLine": "x foo"})


def test_engine_condition_precedence_and_patterns():
    det = {"sel_a": {"A": "1"}, "sel_b": {"B": "1"}, "filter": {"C": "1"},
           "condition": "1 of sel_* and not filter"}
    r = make(det)
    assert r.matches({"A": "1"})
    assert not r.matches({"A": "1", "C": "1"})
    r2 = make({**det, "condition": "all of them"})
    assert r2.matches({"A": "1", "B": "1", "C": "1"})
    r3 = make({**det, "condition": "(sel_a or sel_b) and not filter"})
    assert r3.matches({"B": "1"})


def test_engine_exists_and_missing_field():
    r = make({"sel": {"errorCode|exists": True}, "condition": "not sel"})
    assert r.matches({"x": 1})
    assert not r.matches({"errorCode": "AccessDenied"})


def test_engine_rejects_unknown_modifier():
    with pytest.raises(SigmaError):
        make({"sel": {"A|base64": "x"}, "condition": "sel"}).matches({"A": "x"})


def test_engine_rejects_bad_condition():
    with pytest.raises(SigmaError):
        make({"sel": {"A": "x"}, "condition": "sel and nope"}).matches({"A": "x"})
