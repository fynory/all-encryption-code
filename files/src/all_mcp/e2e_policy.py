"""The device's read of the ALL 2.0 policy table (contracts/policy.json, the contract).

The device payload holds only `src/`, so it cannot read `contracts/` at run time: `e2e_policy.json` next to this file is a byte-identical copy that
the generator's `sync` command writes and its `sync --check` compares (the contract test suite). Code never types a number or a pattern of the table
again: it asks for it by its dotted name, `value("surface.body_max_bytes")`, and the generator's lint refuses a copy.
"""
from __future__ import annotations

import functools
import json
import re
from pathlib import Path
from typing import Any

POLICY_FILE = Path(__file__).with_name("e2e_policy.json")


@functools.lru_cache(maxsize=1)
def load() -> dict[str, Any]:
    return json.loads(POLICY_FILE.read_text(encoding="utf-8"))


def value(dotted: str) -> Any:
    """`value("protocol.line_max_bytes")`: the one way this device reads a number, a word or a list of the table."""
    node: Any = load()
    for part in dotted.split("."):
        node = node[part]
    return node


def anchored(dotted: str) -> re.Pattern[str]:
    """The table's `^...$` pattern as a compiled one to use with `fullmatch` (Python's `$` also matches before a final newline, so the anchors are
    dropped, the way the contract verifiers do)."""
    pattern = value(dotted)
    if not (pattern.startswith("^") and pattern.endswith("$")):
        raise ValueError("policy patterns are anchored: " + dotted)
    return re.compile(pattern[1:-1])


def host_pattern(zone: str) -> re.Pattern[str]:
    """The detector this device builds for ITS OWN address in a zone: the table's label pattern, one dot, the zone. Anchored with \\A and \\Z, so
    match, search and fullmatch give the verdict the Go and TypeScript detectors give."""
    return re.compile(r"\A" + value("identity.label_regex")[1:-1] + r"\." + re.escape(zone) + r"\Z")
