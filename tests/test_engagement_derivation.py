"""P7: the two derivations of `roeEnabled` agree, and no service reads the column.

`roeEnabled` used to be a writable master switch. That made it a bypass shipped
as a checkbox: one write of false and the rate ceiling, the excluded hosts and
the time window all stopped applying at once, while every other field still
showed its configured value.

It is derived now, and derived in two languages, because the webapp cannot
import Python. Two implementations of one safety rule is the drift risk this
file exists to remove: both read the SAME fixture table, so adding a row here
tests both, and changing one implementation without the other fails on one side.

The second half is the blast radius. The rule is only true if nobody reads the
column: a service still mapping it would gate on something nothing writes, and
its half of the enforcement would silently stop.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from recon_settings.engagement import derive_roe_enabled

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "webapp" / "src" / "lib" / "engagement.derivation.fixtures.json"


def _cases() -> list[dict]:
    return json.loads(FIXTURES.read_text(encoding="utf-8"))["cases"]


def test_the_fixture_table_is_a_real_set():
    """A table that shrank to nothing would make every assertion below vacuous."""
    assert len(_cases()) >= 12


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_python_derivation_matches_the_shared_table(case):
    assert derive_roe_enabled(case["row"]) is case["enabled"]


def test_the_stored_column_is_never_consulted():
    """Set both ways round: the column must change nothing, either direction."""
    assert derive_roe_enabled({"roeEnabled": True, "roeGlobalMaxRps": 0}) is False
    assert derive_roe_enabled({"roeEnabled": False, "roeGlobalMaxRps": 3}) is True


def test_a_partial_row_fails_toward_refusing_rather_than_widening():
    """A missing key reads as "no limit of that kind".

    The direction matters. Reading a missing key as a limit that IS set would
    make the derivation claim limits are live when nothing applies them; reading
    it as absent can only fail to switch limits on, which refuses a third-party
    scan rather than widening one.
    """
    assert derive_roe_enabled({}) is False
    assert derive_roe_enabled(None) is False


def test_it_never_raises_on_a_malformed_row():
    """It runs on the path that decides whether a rate ceiling applies.

    A raise here would be a scan that starts without one, so every shape a
    caller could hand it - a string where a list belongs, a non-numeric ceiling -
    answers rather than throws.
    """
    for row in [
        {"roeGlobalMaxRps": "not a number"},
        {"roeExcludedHosts": "a.tld"},
        {"roeExcludedHosts": None},
        {"roeTimeWindowEnabled": "yes"},
    ]:
        assert isinstance(derive_roe_enabled(row), bool)


# --- P7's other half: nothing reads the column ---------------------------------------

#: Where the column may legitimately be named.
_ALLOWED = {
    "recon_settings/engagement.py",       # the derivation itself
    "recon_settings/registry.yaml",       # its registry entry, which says it is derived
    "recon_settings/registry.json",       # the built artifact
    "recon_settings/roe_parse_prompt.py",  # generated; names every column it knows
    "tests/test_engagement_derivation.py",
}

_SEARCH_ROOTS = ("agentic", "recon", "recon_orchestrator", "recon_settings", "graph_db", "mcp")


def _offenders() -> list[str]:
    out: list[str] = []
    for root in _SEARCH_ROOTS:
        base = REPO_ROOT / root
        if not base.is_dir():
            continue
        for path in base.rglob("*.py"):
            rel = path.relative_to(REPO_ROOT).as_posix()
            if rel in _ALLOWED or "/tests/" in rel or rel.startswith("tests/"):
                continue
            if "__pycache__" in rel:
                continue
            for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").split("\n"), 1):
                if "roeEnabled" not in line:
                    continue
                # A comment explaining the derivation is the point, not a reader.
                if re.match(r"^\s*#", line):
                    continue
                out.append(f"{rel}:{i}: {line.strip()}")
    return out


def test_no_python_service_reads_the_roe_enabled_column():
    assert _offenders() == []
