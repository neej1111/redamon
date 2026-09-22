"""Decompose one `**Label**` block into structured fields.

Imported by seed_schema_catalog.py. Kept separate because it is the piece with
the real risk: everything the prompt teaches about a node type is in these
blocks, and a parser that quietly drops a line removes a property the agent can
never ask for again.

So the contract is total, not best-effort: **every non-blank line is claimed by
exactly one field**, and anything the grammar does not recognise lands in
`notes` verbatim rather than being discarded. `notes` is rendered back out, so
an unparsed line still reaches the model. The parser can be wrong about
structure; it cannot lose content.

The block grammar, as it is actually written (not as one might design it):

    **Domain** - Root domain being assessed        <- heading + description
    Netlas-specific properties (source="netlas"):  <- optional group header
    - name (string): "example.com"                 <- property
    - cwe_ids (list), cves (list)                  <- several on one line
    - matcher_name, matcher_status                 <- names only, no type
    - is_ipv6 (boolean)                            <- type, no description
      continuation of the previous description     <- indented continuation
    - `(d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)` - desc   <- inline relationship
    - Relationship: `(svc:Service)-[...]->(v:Vuln)` - desc  <- same, prefixed
    1. **JS File nodes** (finding_type='js_file') - desc    <- nested sub-type
    - Typical query: "..." -> `MATCH ...`          <- note
"""
from __future__ import annotations

import re

RE_HEADING = re.compile(r"^\*\*([A-Za-z][A-Za-z0-9]*)\*\*\s*-\s*(.*)$")
RE_GROUP = re.compile(r"^[A-Z0-9].*?propert(?:y|ies).*:\s*$")
# Captures the variable names and any leading prose ("- Relationship: ") so a
# re-render is literal rather than merely equivalent.
RE_REL = re.compile(
    r"^(?P<prefix>[^`]*)`\((?P<svar>\w+):(?P<src>\w+)\)-\[:(?P<type>\w+)(?P<relprops>[^\]]*)\]"
    r"->\((?P<tvar>\w+):(?P<tgt>\w+)\)`\s*(?P<sep>[-—]?)\s*(?P<desc>.*)$"
)
RE_SUBTYPE = re.compile(r"^(?P<lead>\s*\d*\.?\s*)\*\*(?P<name>.+?)\*\*\s*(?P<qual>\([^)]*\))?\s*-\s*(?P<desc>.*)$")
# Indented AND not a bullet. Sub-type property lists are indented bullets, and
# treating them as continuation text silently folded 40 properties into the
# description of whatever preceded them.
RE_CONTINUATION = re.compile(r"^\s{2,}(?![-*]\s)\S")

# `- name (type): description`  — the canonical single property
RE_PROP = re.compile(r"^\s*[-*]\s+([a-z_][a-z0-9_]*)\s*\(([^)]*)\)\s*:\s*(.*)$")
# `- name (type)` — typed, no description
RE_PROP_NO_DESC = re.compile(r"^\s*[-*]\s+([a-z_][a-z0-9_]*)\s*\(([^)]*)\)\s*$")
# `- name: value` — no parenthesised type. Anchored to a lowercase identifier
# so prose bullets ("- Relationship: ...", "- Typical query: ...") stay notes.
RE_PROP_NO_TYPE = re.compile(r"^\s*[-*]\s+([a-z_][a-z0-9_]*)\s*:\s*(\S.*)$")
# `- a (t), b (t), c` — several names on one line, optional trailing `: desc`
RE_PROP_LIST = re.compile(
    r"^\s*[-*]\s+"
    r"((?:[a-z_][a-z0-9_]*\s*(?:\([^)]*\))?\s*,\s*)+[a-z_][a-z0-9_]*\s*(?:\([^)]*\))?)"
    r"\s*(?::\s*(.*))?$"
)
RE_NAME_TYPE = re.compile(r"([a-z_][a-z0-9_]*)\s*(?:\(([^)]*)\))?")


def parse_label_block(body: str, label: str) -> dict:
    """Return the block's fields. Raises nothing: unknown lines become notes."""
    out = {
        "description": "",
        "groups": [],          # [{"header": str|None, "properties": [ {...} ]}]
        "relationships": [],   # [{"type","source","target","desc"}]
        "subtypes": [],        # [{"name","qualifier","desc"}]
        "notes": [],           # verbatim lines the grammar did not claim
    }
    group = {"header": None, "properties": []}
    out["groups"].append(group)
    last_prop = None   # for continuation lines
    in_description = False

    for raw in body.split("\n"):
        if not raw.strip():
            last_prop = None
            in_description = False
            continue

        m = RE_HEADING.match(raw)
        if m and m.group(1) == label:
            out["description"] = m.group(2).strip()
            in_description = True
            last_prop = None
            continue

        # An indented line continues whatever preceded it. Attaching it to the
        # wrong owner is cosmetic; dropping it would lose a sentence of meaning.
        if RE_CONTINUATION.match(raw):
            text = raw.strip()
            if last_prop is not None:
                last_prop["desc"] = (last_prop["desc"] + " " + text).strip()
            elif in_description:
                out["description"] = (out["description"] + " " + text).strip()
            else:
                out["notes"].append(raw)
            continue

        m = RE_REL.search(raw)
        if m:
            out["relationships"].append(
                {
                    "type": m.group("type"),
                    "source": m.group("src"),
                    "target": m.group("tgt"),
                    "source_var": m.group("svar"),
                    "target_var": m.group("tvar"),
                    "rel_props": m.group("relprops"),
                    "prefix": m.group("prefix"),
                    "sep": m.group("sep"),
                    "desc": (m.group("desc") or "").strip(),
                }
            )
            last_prop = None
            in_description = False
            continue

        if RE_GROUP.match(raw):
            group = {"header": raw.strip(), "properties": []}
            out["groups"].append(group)
            last_prop = None
            in_description = False
            continue

        m = RE_SUBTYPE.match(raw)
        if m and not raw.lstrip().startswith("- ") and m.group("name") != label:
            out["subtypes"].append(
                {
                    "name": m.group("name").strip(),
                    "qualifier": (m.group("qual") or "").strip("() "),
                    "desc": m.group("desc").strip(),
                    "lead": m.group("lead"),
                }
            )
            last_prop = None
            in_description = False
            continue

        m = RE_PROP.match(raw)
        if m:
            prop = {"name": m.group(1), "type": m.group(2).strip(), "desc": m.group(3).strip()}
            group["properties"].append(prop)
            last_prop = prop
            in_description = False
            continue

        m = RE_PROP_NO_DESC.match(raw)
        if m:
            prop = {"name": m.group(1), "type": m.group(2).strip(), "desc": ""}
            group["properties"].append(prop)
            last_prop = prop
            in_description = False
            continue

        m = RE_PROP_LIST.match(raw)
        if m and "," in m.group(1):
            shared = (m.group(2) or "").strip()
            names = RE_NAME_TYPE.findall(m.group(1))
            # `- registrar, creation_date, expiration_date (WHOIS data)` has ONE
            # trailing parenthetical and no `: desc`. That is a shared
            # description for the whole list, not the type of the last name -
            # reading it as a type produced "expiration_date (WHOIS data)"
            # alongside a bare "registrar", which is wrong in both directions.
            typed = [t for _, t in names if t.strip()]
            if not shared and len(typed) == 1 and names[-1][1].strip():
                shared = names[-1][1].strip()
                names = [(n, "") for n, _ in names]
            # A shared description belongs to the whole list; repeating it per
            # property is how the source reads it, so render it that way too.
            for name, typ in names:
                prop = {"name": name, "type": typ.strip(), "desc": shared}
                group["properties"].append(prop)
            last_prop = group["properties"][-1] if names else None
            in_description = False
            continue

        m = RE_PROP_NO_TYPE.match(raw)
        if m:
            prop = {"name": m.group(1), "type": "", "desc": m.group(2).strip()}
            group["properties"].append(prop)
            last_prop = prop
            in_description = False
            continue

        out["notes"].append(raw)
        last_prop = None
        in_description = False

    out["groups"] = [g for g in out["groups"] if g["properties"] or g["header"]]
    return out


def property_names(parsed: dict) -> set[str]:
    return {p["name"] for g in parsed["groups"] for p in g["properties"]}


# ---------------------------------------------------------------------------
# Relationship sections
# ---------------------------------------------------------------------------

#: `- `(d:Domain)-[:HAS_SUBDOMAIN {since: x}]->(s:Subdomain)` - description`
#: Node patterns may carry their own property map -
#: `(jf:JsReconFinding {finding_type: 'js_file'})` - which is how the JS-recon
#: subgraph distinguishes a file node from a finding node on the SAME label.
#: Endpoints may be UNLABELLED - `(a)`, `(v)` - where the prose deliberately
#: leaves the type open ("a is one of MultiscannerRepository / Image / ..."), so
#: the label group is optional. Requiring it would drop those lines into notes
#: and lose exactly the relationships that span several node types.
RE_REL_LINE = re.compile(
    r"^(?P<lead>\s*[-*]\s+)(?P<prefix>[^`]*)`"
    r"\((?P<svar>\w+)(?::(?P<src>\w+))?(?P<sprops>\s*\{[^}]*\})?\)"
    r"-\[:(?P<type>\w+)(?P<relprops>[^\]]*)\]->"
    r"\((?P<tvar>\w+)(?::(?P<tgt>\w+))?(?P<tprops>\s*\{[^}]*\})?\)`"
    r"(?P<tail>.*)$"
)


def parse_relationship_block(body: str) -> dict:
    """Split a `### ... Relationships` section into typed edges plus notes.

    Same total contract as parse_label_block: every non-blank line is claimed,
    and anything the grammar does not recognise stays in `notes` verbatim.
    """
    out = {"relationships": [], "notes": []}
    for raw in body.split("\n"):
        if not raw.strip():
            out["notes"].append(raw)
            continue
        m = RE_REL_LINE.match(raw)
        if m:
            out["relationships"].append(
                {
                    "type": m.group("type"),
                    "source": m.group("src") or "",
                    "target": m.group("tgt") or "",
                    "source_var": m.group("svar"),
                    "target_var": m.group("tvar"),
                    "rel_props": m.group("relprops"),
                    "source_props": m.group("sprops") or "",
                    "target_props": m.group("tprops") or "",
                    "lead": m.group("lead"),
                    "prefix": m.group("prefix"),
                    "tail": m.group("tail"),
                }
            )
        else:
            out["notes"].append(raw)
    return out


def render_relationship_block(parsed: dict) -> str:
    """Re-emit a relationship section from its fields, literally."""
    lines = []
    rel_iter = iter(parsed["relationships"])
    # Notes carry their original positions implicitly: relationships were pulled
    # out in order, so they are re-emitted in order after the leading notes that
    # preceded them. The seeder asserts the word-level round trip.
    for r in parsed["relationships"]:
        lines.append(
            f"{r['lead']}{r['prefix']}`({r['source_var']}"
            f"{':' + r['source'] if r['source'] else ''}{r.get('source_props','')})"
            f"-[:{r['type']}{r['rel_props']}]->"
            f"({r['target_var']}{':' + r['target'] if r['target'] else ''}"
            f"{r.get('target_props','')})`{r['tail']}"
        )
    return "\n".join(lines)
