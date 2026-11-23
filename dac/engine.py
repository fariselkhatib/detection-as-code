"""A small Sigma evaluator for unit-testing rules against JSON events.

This is not a SIEM backend. It implements the subset of Sigma that the rules in this
repo use, so every rule can be tested against true-positive and false-positive events
in CI before it ever reaches production:

  - selections as maps (AND of fields) or lists of maps (OR)
  - value lists (OR), or AND with the |all modifier
  - modifiers: contains, startswith, endswith, re, all, exists
  - conditions: and / or / not, parentheses, "1 of x*", "all of x*", "1 of them", "all of them"

String matching is case-insensitive except |re, which follows the Sigma spec (case-sensitive
unless the pattern says otherwise).
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "exists"}


class SigmaError(ValueError):
    pass


@dataclass
class Rule:
    path: Path
    raw: dict

    @property
    def id(self) -> str:
        return self.raw["id"]

    @property
    def title(self) -> str:
        return self.raw["title"]

    def matches(self, event: dict) -> bool:
        det = self.raw["detection"]
        selections = {k: v for k, v in det.items() if k != "condition"}
        return _eval_condition(det["condition"], selections, event)


def load_rule(path: str | Path) -> Rule:
    path = Path(path)
    with path.open(encoding="utf-8") as fh:
        return Rule(path, yaml.safe_load(fh))


def load_rules(root: str | Path) -> list[Rule]:
    return [load_rule(p) for p in sorted(Path(root).rglob("*.yml"))]


# --- field matching -------------------------------------------------------

def _match_field(key: str, expected, event: dict) -> bool:
    field, *mods = key.split("|")
    unknown = set(mods) - SUPPORTED_MODIFIERS
    if unknown:
        raise SigmaError(f"unsupported modifier(s) {sorted(unknown)} on {key}")

    if "exists" in mods:
        return (field in event and event[field] is not None) == bool(expected)

    if field not in event or event[field] is None:
        return False
    actual = str(event[field])
    values = expected if isinstance(expected, list) else [expected]

    def one(v) -> bool:
        v = str(v)
        if "re" in mods:
            return re.search(v, actual) is not None
        a, b = actual.lower(), v.lower()
        if "contains" in mods:
            return b in a
        if "startswith" in mods:
            return a.startswith(b)
        if "endswith" in mods:
            return a.endswith(b)
        return a == b

    return all(one(v) for v in values) if "all" in mods else any(one(v) for v in values)


def _match_selection(sel, event: dict) -> bool:
    if isinstance(sel, list):  # list of maps = OR
        return any(_match_selection(s, event) for s in sel)
    if isinstance(sel, dict):  # map = AND across fields
        return all(_match_field(k, v, event) for k, v in sel.items())
    raise SigmaError(f"unsupported selection type: {type(sel).__name__}")


# --- condition parsing (recursive descent) --------------------------------

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def _tokenize(cond: str) -> list[str]:
    pos, out = 0, []
    cond = cond.strip()
    while pos < len(cond):
        m = _TOKEN.match(cond, pos)
        if not m:
            raise SigmaError(f"cannot parse condition near: {cond[pos:]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


def _eval_condition(cond: str, selections: dict, event: dict) -> bool:
    tokens = _tokenize(cond)
    pos = 0

    def peek():
        return tokens[pos].lower() if pos < len(tokens) else None

    def take():
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def sel(name):
        if name not in selections:
            raise SigmaError(f"condition references unknown selection {name!r}")
        return _match_selection(selections[name], event)

    def expr():
        val = term()
        while peek() == "or":
            take()
            rhs = term()
            val = val or rhs
        return val

    def term():
        val = factor()
        while peek() == "and":
            take()
            rhs = factor()
            val = val and rhs
        return val

    def factor():
        tok = peek()
        if tok is None:
            raise SigmaError("unexpected end of condition")
        if tok == "not":
            take()
            return not factor()
        if tok == "(":
            take()
            val = expr()
            if take() != ")":
                raise SigmaError("missing )")
            return val
        if tok in ("1", "all"):
            quant = take().lower()
            if take().lower() != "of":
                raise SigmaError("expected 'of'")
            pattern = take()
            names = list(selections) if pattern == "them" else fnmatch.filter(selections, pattern)
            if not names:
                raise SigmaError(f"pattern {pattern!r} matches no selections")
            results = [sel(n) for n in names]
            return any(results) if quant == "1" else all(results)
        return sel(take())

    result = expr()
    if pos != len(tokens):
        raise SigmaError(f"trailing tokens in condition: {tokens[pos:]}")
    return result
