"""Rule quality gates. Every rule must pass these before it can merge."""
from __future__ import annotations

import re
import uuid
from datetime import date
from pathlib import Path

from .engine import Rule

REQUIRED = ["title", "id", "status", "description", "references", "author", "date",
            "tags", "logsource", "detection", "falsepositives", "level"]
LEVELS = {"informational", "low", "medium", "high", "critical"}
STATUSES = {"stable", "test", "experimental"}
TACTICS = {"reconnaissance", "resource-development", "initial-access", "execution", "persistence",
           "privilege-escalation", "defense-evasion", "credential-access", "discovery",
           "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"}
TECHNIQUE_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")


def validate_rule(rule: Rule, fixtures_dir: Path) -> list[str]:
    r, errs = rule.raw, []
    name = rule.path.name

    for key in REQUIRED:
        if key not in r or r[key] in (None, "", []):
            errs.append(f"{name}: missing '{key}'")
    if errs:
        return errs

    try:
        uuid.UUID(str(r["id"]))
    except ValueError:
        errs.append(f"{name}: id is not a UUID")
    if len(r["title"]) > 110:
        errs.append(f"{name}: title over 110 chars")
    if r["level"] not in LEVELS:
        errs.append(f"{name}: invalid level {r['level']!r}")
    if r["status"] not in STATUSES:
        errs.append(f"{name}: invalid status {r['status']!r}")
    if not isinstance(r["date"], date):
        errs.append(f"{name}: date must be YYYY-MM-DD")
    if "condition" not in r["detection"]:
        errs.append(f"{name}: detection has no condition")

    tags = r["tags"]
    techniques = [t for t in tags if TECHNIQUE_TAG.match(t)]
    tactics = [t.split(".", 1)[1] for t in tags if t.startswith("attack.") and not TECHNIQUE_TAG.match(t)]
    if not techniques:
        errs.append(f"{name}: needs at least one attack.tXXXX technique tag")
    if not tactics:
        errs.append(f"{name}: needs at least one ATT&CK tactic tag")
    for t in tactics:
        if t not in TACTICS:
            errs.append(f"{name}: unknown tactic tag attack.{t}")

    fixture = fixtures_dir / f"{rule.path.stem}.json"
    if not fixture.exists():
        errs.append(f"{name}: no test fixture at tests/fixtures/{fixture.name}")
    return errs


def validate_all(rules: list[Rule], fixtures_dir: Path) -> list[str]:
    errs = [e for rule in rules for e in validate_rule(rule, fixtures_dir)]
    seen = {}
    for rule in rules:
        rid = rule.raw.get("id")
        if rid in seen:
            errs.append(f"{rule.path.name}: duplicate id with {seen[rid]}")
        seen[rid] = rule.path.name
    return errs
