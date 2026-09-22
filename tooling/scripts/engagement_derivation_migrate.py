#!/usr/bin/env python3
"""Report every project whose stored `roeEnabled` disagrees with the derived one.

DRY RUN BY DEFAULT.

WHY THIS EXISTS

`roeEnabled` stopped being a writable master switch and became a derivation:
the engagement's limits apply when there IS a limit to apply, that is, a
non-zero `roeGlobalMaxRps`, OR a non-empty `roeExcludedHosts`, OR
`roeTimeWindowEnabled`. Nothing writes the column any more and every service
computes the value through `recon_settings.engagement.derive_roe_enabled`.

For most rows the two agree and nothing changes. The rows that matter are the
ones where they disagree, and they disagree in two directions:

  stored FALSE, derived TRUE   limits were configured and inert. They become
                               live on the next scan. Strictly more restrictive,
                               so no scan becomes more aggressive - but see the
                               time-window caveat below.
  stored TRUE, derived FALSE   the switch was on with nothing behind it. Nothing
                               was being enforced before either, because there
                               was no ceiling, no exclusion and no window. The
                               only change is that the UI stops implying there
                               was.

THE ONE CASE THAT BREAKS A WORKING SETUP

Every flip is toward more restrictive, so nothing scans harder. But a flip
caused by `roeTimeWindowEnabled` is different in kind from one caused by a rate
ceiling: the orchestrator returns HTTP 403 and REFUSES a scan start outside the
window, rather than slowing it down. A nightly scan at 03:00 against a
09:00-17:00 window stops running rather than running gently.

Those rows are listed separately, because they are the only ones an operator has
to act on rather than merely know about.

WHAT --apply DOES

It writes an `AuditLog` row per disagreeing project naming the row and the
reason, and nothing else. It does NOT change any project: the column is no
longer authoritative, so rewriting it would be writing a value nothing reads.
The audit trail is the whole point - it is how an operator finds out afterwards
why a project acquired limits it did not set today.

  # see what would be recorded, change nothing (the default)
  python tooling/scripts/engagement_derivation_migrate.py

  # write the audit rows
  python tooling/scripts/engagement_derivation_migrate.py --apply

Idempotent: running it twice records the same rows twice only if --apply is
passed twice, and each row is timestamped, so a duplicate is visible as one.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from recon_settings.engagement import derive_roe_enabled  # noqa: E402

AUDIT_ACTION = "engagement.limits_derived"


def _connect():
    """A psycopg connection from DATABASE_URL, or a clear refusal."""
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise SystemExit(
            "DATABASE_URL is not set. This reads the projects table directly, so it needs "
            "the same connection string the webapp uses."
        )
    try:
        import psycopg
    except ImportError:  # pragma: no cover - only outside the images that have it
        raise SystemExit(
            "psycopg is required. Run this inside the webapp or agent container, where it "
            "is installed, rather than on the host."
        )
    return psycopg.connect(url)


#: The columns the derivation reads, plus what identifies the row in a report.
_SELECT = """
    SELECT id, name, roe_enabled, roe_global_max_rps, roe_excluded_hosts,
           roe_time_window_enabled, engagement_kind
      FROM projects
     ORDER BY created_at
"""


def classify(row: dict) -> dict | None:
    """The disagreement for one row, or None when the two agree."""
    project = {
        "roeGlobalMaxRps": row["roe_global_max_rps"],
        "roeExcludedHosts": row["roe_excluded_hosts"] or [],
        "roeTimeWindowEnabled": row["roe_time_window_enabled"],
    }
    derived = derive_roe_enabled(project)
    stored = bool(row["roe_enabled"])
    if derived == stored:
        return None

    reasons = []
    if (row["roe_global_max_rps"] or 0) > 0:
        reasons.append(f"a rate ceiling of {row['roe_global_max_rps']} rps")
    if any(str(h).strip() for h in (row["roe_excluded_hosts"] or [])):
        reasons.append(f"{len(row['roe_excluded_hosts'])} excluded host(s)")
    if row["roe_time_window_enabled"]:
        reasons.append("a scanning time window")

    return {
        "projectId": row["id"],
        "name": row["name"],
        "engagementKind": row["engagement_kind"],
        "stored": stored,
        "derived": derived,
        "reasons": reasons,
        # The only flip that STOPS a scan rather than slowing one.
        "blocksScansOutsideWindow": bool(derived and row["roe_time_window_enabled"]),
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write the audit rows")
    args = parser.parse_args(argv)

    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(_SELECT)
            columns = [c.name for c in cur.description]
            rows = [dict(zip(columns, r)) for r in cur.fetchall()]

        flips = [c for c in (classify(r) for r in rows) if c]

        print(f"{len(rows)} project(s) inspected, {len(flips)} disagree with the derivation.")
        if not flips:
            print("Nothing to record.")
            return 0

        gaining = [f for f in flips if f["derived"]]
        losing = [f for f in flips if not f["derived"]]
        window = [f for f in flips if f["blocksScansOutsideWindow"]]

        if gaining:
            print(f"\n{len(gaining)} project(s) ACQUIRE live limits on their next scan:")
            for f in gaining:
                print(f"  {f['projectId']}  {f['name']}: {', '.join(f['reasons'])}")

        if losing:
            print(f"\n{len(losing)} project(s) had the switch on with nothing behind it:")
            for f in losing:
                print(f"  {f['projectId']}  {f['name']}: no ceiling, no exclusions, no window")

        if window:
            # Listed separately because these are the only ones that STOP a scan
            # rather than slow one: outside the window the orchestrator returns
            # 403 instead of queueing.
            print(f"\n*** {len(window)} project(s) will REFUSE a scan outside their time window:")
            for f in window:
                print(f"  {f['projectId']}  {f['name']}")
            print("    A scheduled scan outside the window stops running rather than running")
            print("    gently. Check the window, or clear it if it was never meant to apply.")

        if not args.apply:
            print("\nDRY RUN: nothing was written. Pass --apply to record the audit rows.")
            return 0

        with conn.cursor() as cur:
            for f in flips:
                cur.execute(
                    """
                    INSERT INTO audit_log (id, actor_id, action, target_type, target_id,
                                           before, after, source, created_at)
                    VALUES (gen_random_uuid()::text, NULL, %s, 'project', %s, %s, %s,
                            'system', now())
                    """,
                    (
                        AUDIT_ACTION,
                        f["projectId"],
                        json.dumps({"roeEnabled": f["stored"]}),
                        json.dumps({
                            "roeEnabledDerived": f["derived"],
                            "because": f["reasons"],
                            "blocksScansOutsideWindow": f["blocksScansOutsideWindow"],
                            "note": (
                                "roeEnabled is derived from whether any engagement limit is "
                                "set. The stored column is no longer read."
                            ),
                        }),
                    ),
                )
        conn.commit()
        print(f"\nRecorded {len(flips)} audit row(s) with action '{AUDIT_ACTION}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
