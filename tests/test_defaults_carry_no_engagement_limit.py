"""P16: `/api/projects/defaults` never carries an engagement limit.

The obvious reading is that this is tidiness - a limit has no global default,
because it belongs to one engagement rather than to the installation. It is not.

`applyPreset` in `ProjectForm.tsx` RESETS every form field that appears in the
defaults payload before applying the preset, and only then overlays the preset's
own values. So a `roeGlobalMaxRps: 0` in that payload silently zeroes a
configured rate ceiling, and a `roeExcludedHosts: []` empties the never-touch
list, on every preset apply. The comment in `applyPreset` records the property
this test exists to keep true: the payload carries no engagement key, so the
spread base preserves what the operator entered.

It used to hold by accident, because the whole block was a separate disposition
nothing derived a default from. Now that the limits are ordinary settable fields
and the payload is registry-derived, it holds only because it is enforced.
"""
from __future__ import annotations

import re
from pathlib import Path

from recon_settings.engagement import (
    engagement_limit_columns,
    engagement_record_columns,
    strip_engagement_limits,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_the_helper_removes_every_engagement_limit():
    limits = engagement_limit_columns()
    assert len(limits) >= 15
    payload = {c: "whatever" for c in limits}
    payload["naabuThreads"] = 25
    assert strip_engagement_limits(payload) == {"naabuThreads": 25}


def test_it_removes_the_ones_that_would_actually_bite():
    """Named, because these three are the values a preset apply would destroy."""
    payload = {
        "roeGlobalMaxRps": 0,
        "roeExcludedHosts": [],
        "roeTimeWindowEnabled": False,
        "naabuRateLimit": 1000,
    }
    assert strip_engagement_limits(payload) == {"naabuRateLimit": 1000}


def test_it_leaves_the_engagement_RECORD_alone():
    """The record is not a limit and is not in the payload for a different reason.

    It is `mcp: never`, so nothing derives a default from it either - but if one
    ever appeared there, stripping it HERE would hide the real problem. This
    helper has one job.
    """
    payload = {c: "x" for c in engagement_record_columns()}
    assert strip_engagement_limits(dict(payload)) == payload


def test_it_is_a_registry_query_rather_than_a_list():
    """A snapshot of the answer would stop covering a newly classified limit."""
    source = (REPO_ROOT / "recon_settings" / "engagement.py").read_text(encoding="utf-8")
    body = source[source.index("def strip_engagement_limits"):]
    assert "engagement_limit_columns()" in body
    # No literal column names in the body.
    named = {
        m.group(1)
        for m in re.finditer(r"""["']([a-z][A-Za-z0-9]{5,})["']""", body)
    } & set(engagement_limit_columns())
    assert named == set()


def test_both_defaults_endpoints_call_the_one_helper():
    """Two endpoints merge into one payload; a rule in only one of them is half a rule."""
    for rel in ("recon_orchestrator/api.py", "agentic/api.py"):
        source = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert "strip_engagement_limits" in source, rel


def test_the_orchestrator_strips_AFTER_it_builds_the_payload():
    """Order matters: stripping before the camel-casing would strip nothing.

    The six limits the agent enforces alone have no recon runtime key, so they
    only become visible once the payload is keyed by COLUMN.
    """
    source = (REPO_ROOT / "recon_orchestrator" / "api.py").read_text(encoding="utf-8")
    built = source.index("camel_case_defaults = {")
    stripped = source.index("strip_engagement_limits(camel_case_defaults)")
    assert built < stripped
