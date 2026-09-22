"""Compose the graph-schema document: invariant rules + generated schema.

The two halves live apart because they go stale for different reasons, or not at
all:

- `TEXT_TO_CYPHER_SYSTEM` (agentic/prompts/base.py) holds what does NOT follow
  the data model: label every node pattern, Muted findings are invisible,
  read-only, relationship direction matters, the worked query patterns, the AI
  surface annotations, the output format. Those change when the RULES change.

- `graph_db/schema_catalog.py` holds the node types, their properties and the
  relationships. Those change whenever a scanner writes something new, which is
  constantly, and which is why they were the half that drifted: 12 labels and
  134 properties had gone undocumented before anyone noticed, because forgetting
  to edit 1300 lines of prose fails silently.

The splice point is the literal marker `__GRAPH_SCHEMA__`, replaced with
`str.replace`. Deliberately NOT `str.format`: the prompt is full of Cypher maps
like `{name: "x"}`, and format() would read every one as a field reference. The
same prompt already carried 19 doubled-brace escapes left over from a previous
format()-based consumer, which taught the model invalid Cypher for months.
"""
from __future__ import annotations

MARKER = "__GRAPH_SCHEMA__"


def build_schema_document() -> str:
    """The full document the Cypher generator and `graph_schema` both serve."""
    from graph_db.schema_render import render_schema
    from prompts import TEXT_TO_CYPHER_SYSTEM

    schema = render_schema()
    if MARKER not in TEXT_TO_CYPHER_SYSTEM:
        # Fail loudly rather than silently serving rules with no schema: the
        # model would still answer, confidently, about node types it was never
        # shown.
        raise RuntimeError(
            f"{MARKER} is missing from TEXT_TO_CYPHER_SYSTEM; the generated "
            "schema has nowhere to go."
        )
    return TEXT_TO_CYPHER_SYSTEM.replace(MARKER, schema.rstrip("\n"))
