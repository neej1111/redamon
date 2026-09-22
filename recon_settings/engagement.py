"""One derivation of "are the engagement limits live", for every service.

`roeEnabled` used to be a writable master switch, and that made it a bypass
shipped as a checkbox: one write of false and the rate ceiling, the excluded
hosts and the time window all stopped applying at once, while every other field
still showed its configured value. Nothing about the project looked different.

So it is derived instead. Limits apply when there is a limit to apply:

    a non-zero rate ceiling, OR a non-empty exclusion list, OR a time window.

The column survives in Prisma so old rows and old exports still load, and
nothing writes it. Four Python call sites and one TypeScript one used to map it
independently; they all come here now, except the TypeScript one, which cannot
import Python and is pinned to this rule by a shared fixture table instead
(`deriveRoeEnabled` in `webapp/src/lib/engagement.ts`).

Deliberately dependency-free and exception-free: this is imported inside a scan
container on the path that decides whether a rate ceiling applies, and a raise
here would be a scan that starts without one.
"""
from __future__ import annotations

from typing import Any, Mapping

from .loader import fields_where

ENGAGEMENT_LIMIT_GROUP = "engagement_limits"
ENGAGEMENT_RECORD_REASON = "engagement-record"

#: The column the derivation replaces. Kept for readers, never written.
DERIVED_COLUMN = "roeEnabled"


def _truthy_ceiling(value: Any) -> bool:
    try:
        return float(value) > 0
    except (TypeError, ValueError):
        return False


def _non_empty(value: Any) -> bool:
    if isinstance(value, (list, tuple, set)):
        return any(str(v).strip() for v in value)
    if isinstance(value, str):
        return bool(value.strip())
    return False


def derive_roe_enabled(project: Mapping[str, Any] | None) -> bool:
    """Are this project's engagement limits live?

    Takes a Prisma-shaped row (camelCase keys), which is what every caller
    already holds. A missing key reads as "no limit of that kind", so a partial
    row cannot switch limits ON by accident - it can only fail to switch them
    on, which is the direction that refuses a scan rather than widening one.
    """
    if not project:
        return False
    return (
        _truthy_ceiling(project.get("roeGlobalMaxRps"))
        or _non_empty(project.get("roeExcludedHosts"))
        or bool(project.get("roeTimeWindowEnabled"))
    )


def engagement_limit_columns() -> list[str]:
    """The columns the derivation governs, from the registry rather than a prefix.

    A name prefix is not a classification: these columns keep their `roe*`
    names while their MEANING changes, so anything keyed on the prefix survives
    that change by accident. Callers that need "the engagement limits" ask here.
    """
    return sorted(
        key
        for key, spec in fields_where(
            lambda spec, key: spec.get("group") == ENGAGEMENT_LIMIT_GROUP
        ).items()
    )


def engagement_record_columns() -> list[str]:
    """The contract: who the client is, what the document said. UI-only."""
    return sorted(
        key
        for key, spec in fields_where(
            lambda spec, key: spec.get("deny_reason") == ENGAGEMENT_RECORD_REASON
        ).items()
    )


def strip_engagement_limits(defaults: dict[str, Any]) -> dict[str, Any]:
    """Remove every engagement limit from a served DEFAULTS payload. Mutates.

    A limit has no global default: it is a property of ONE engagement, not of the
    installation. Emitting one is worse than useless, because the ProjectForm's
    preset-apply path resets every form field that appears in this payload BEFORE
    applying the preset - so a `roeGlobalMaxRps: 0` here silently zeroes a
    configured rate ceiling and empties the exclusion list on every preset apply.

    Keyed on the registry GROUP and applied by COLUMN, because the six limits the
    agent enforces alone are named for their columns rather than for a recon
    runtime key the registry would know. One helper, called by both `/defaults`
    endpoints, so the two cannot disagree about what a default is.
    """
    for column in engagement_limit_columns():
        defaults.pop(column, None)
    return defaults
