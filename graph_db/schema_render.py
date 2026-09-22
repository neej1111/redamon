"""Render the graph-schema document from the catalog's structured fields.

Pure: no database, no network, no I/O beyond importing the catalog. That is what
lets `graph_schema` keep its promise of still answering when Neo4j and Postgres
are down, and what makes this unit-testable without a stack.

Node blocks are rendered from PARSED FIELDS - description, property groups,
relationships, sub-types, notes - not from the prose they were seeded with. The
verbatim body stays in the catalog beside them purely as provenance: the tests
re-render every block and assert not one word of the original went missing.

Everything else - the relationship sections, the worked query patterns - is
emitted verbatim, because it is prose about HOW TO QUERY rather than a
description of a node type, and has no field structure to render from.

This module deliberately takes no options. It grew a `detail=`, `labels=` and
`live_properties=` API for a scoping feature that was never wired up, and for a
live-graph merge that became unnecessary once the catalog described every
property. Unused parameters on the one function that builds the agent's view of
the graph are not free: they are a second code path nobody exercises, and
`live_properties` in particular was a second SOURCE waiting to be switched back
on. Scoping can come back when something actually calls it.
"""
from __future__ import annotations

try:  # normal import inside the package
    from graph_db.schema_catalog import LABELS, SEGMENTS
except ImportError:  # loaded by path (pure unit tests, no package side effects)
    from schema_catalog import LABELS, SEGMENTS  # type: ignore


def render_label(label: str) -> str:
    """Render ONE label block from its fields.

    Raises:
        ValueError: on an unknown label. Returning an empty string would read
            exactly like "that node type has no documentation", which is the
            confusion this module exists to end.
    """
    seg = LABELS.get(label)
    if seg is None:
        raise ValueError(
            f"unknown label {label!r}. Known labels: {', '.join(sorted(LABELS))}"
        )

    out = [f"**{label}** - {seg['description']}"]

    for group in seg["groups"]:
        if group["header"]:
            out.append("")
            out.append(group["header"])
        for prop in group["properties"]:
            typ = f" ({prop['type']})" if prop["type"] else ""
            desc = f": {prop['desc']}" if prop["desc"] else ""
            out.append(f"- {prop['name']}{typ}{desc}")

    for sub in seg["subtypes"]:
        qual = f" ({sub['qualifier']})" if sub["qualifier"] else ""
        out.append("")
        out.append(f"{sub.get('lead', '')}**{sub['name']}**{qual} - {sub['desc']}")

    for rel in seg["relationships"]:
        out.append(
            f"{rel.get('prefix', '')}`({rel['source_var']}:{rel['source']})"
            f"-[:{rel['type']}{rel.get('rel_props', '')}]->"
            f"({rel['target_var']}:{rel['target']})` "
            f"{rel.get('sep', '')} {rel['desc']}".rstrip()
        )

    if seg["notes"]:
        out.append("")
        out.extend(n.rstrip() for n in seg["notes"])

    return "\n".join(out) + "\n"


def render_schema() -> str:
    """The whole schema document: every node type and every relationship."""
    return "".join(
        render_label(seg["key"]) if seg["kind"] == "LABEL" else seg["body"]
        for seg in SEGMENTS
    )
