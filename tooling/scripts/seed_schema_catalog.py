#!/usr/bin/env python3
"""Seed `graph_db/schema_catalog.py` from the hand-written prompt.

One-time mechanical job (`graph_schema_track.md` §12.3): slice the 1329-line
`TEXT_TO_CYPHER_SYSTEM` literal into addressable segments and emit them as a
catalog module, so the same content can be rendered per-label instead of only
as one 81KB block.

**The fidelity contract.** Every byte of the source lands in exactly one
segment, and concatenating the segments in order reproduces the source
byte-for-byte. The generator refuses to write if that does not hold, and
`recon/tests/test_schema_catalog.py` re-checks it against the committed
fixture. This is what makes "we lost nothing" a mechanical fact rather than a
claim: the prose is not re-typed, re-wrapped or summarised, only cut.

Bodies are stored verbatim rather than decomposed into per-property dicts. The
prose carries structure a flat `{name, type, desc}` list cannot hold: property
groups (`Nuclei-specific properties (source="nuclei"):`), relationship notes
inside a label block, and single descriptions running to 1800 characters. A
decomposition is still possible later, per label, against a committed baseline
that proves what changed.

Run:
    python3 tooling/scripts/seed_schema_catalog.py [--check]

`--check` verifies the committed catalog still reproduces the fixture without
rewriting it, which is what CI wants.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from parse_label_block import (  # noqa: E402
    parse_label_block,
    parse_relationship_block,
)

REPO = Path(__file__).resolve().parent.parent.parent
#: The schema sections were CUT OUT of TEXT_TO_CYPHER_SYSTEM; this file is
#: what was cut, kept so the catalog can be re-seeded and so the losslessness
#: proof has something to compare against. The catalog is now the source of
#: truth: base.py holds only the invariant rules and a __GRAPH_SCHEMA__ marker.
SEED = REPO / "graph_db" / "schema_sections.md"
FIXTURE = SEED
OUT = REPO / "graph_db" / "schema_catalog.py"

START_TOKEN = 'TEXT_TO_CYPHER_SYSTEM = """'


def extract_prompt() -> str:
    return SEED.read_text(encoding="utf-8")


def segment(doc: str) -> list[dict]:
    """Cut the document on ## / ### headings, then on **Label** blocks.

    Returns segments in source order. Concatenating their bodies reproduces
    `doc` exactly; the caller asserts that.
    """
    segs: list[dict] = []
    h2s = [m.start() for m in re.finditer(r"^## ", doc, re.M)]
    if not h2s:
        return [{"kind": "PREAMBLE", "key": "", "section": "", "body": doc}]

    segs.append({"kind": "PREAMBLE", "key": "", "section": "", "body": doc[: h2s[0]]})

    for a, b in zip(h2s, h2s[1:] + [len(doc)]):
        chunk = doc[a:b]
        title = chunk.split("\n", 1)[0][3:].strip()
        h3s = [m.start() for m in re.finditer(r"^### ", chunk, re.M)]
        if not h3s:
            segs.append({"kind": "SECTION", "key": title, "section": title, "body": chunk})
            continue
        segs.append(
            {"kind": "SECTION_HEAD", "key": title, "section": title, "body": chunk[: h3s[0]]}
        )
        for c, d in zip(h3s, h3s[1:] + [len(chunk)]):
            sub = chunk[c:d]
            subtitle = sub.split("\n", 1)[0][4:].strip()
            labs = [m.start() for m in re.finditer(r"^\*\*[A-Za-z][A-Za-z0-9]*\*\*\s*-", sub, re.M)]
            if not labs:
                segs.append(
                    {
                        "kind": "SUBSECTION",
                        "key": subtitle,
                        "section": title,
                        "body": sub,
                    }
                )
                continue
            segs.append(
                {
                    "kind": "SUBSECTION_HEAD",
                    "key": subtitle,
                    "section": title,
                    "body": sub[: labs[0]],
                }
            )
            for e, f in zip(labs, labs[1:] + [len(sub)]):
                blk = sub[e:f]
                lab = re.match(r"^\*\*([A-Za-z][A-Za-z0-9]*)\*\*", blk).group(1)
                segs.append(
                    {
                        "kind": "LABEL",
                        "key": lab,
                        "section": f"{title} :: {subtitle}",
                        "body": blk,
                    }
                )
    return segs


#: Labels documented as a SHARED group rather than under their own heading.
#: The Secret Multiscanner asset nodes are one shape with five labels, listed
#: backticked inside an "**Asset nodes**" block; detecting them by bold mention
#: would need the block to repeat itself five times for no reader benefit.
GROUP_COVERAGE = {
    "MultiscannerRepository",
    "MultiscannerImage",
    "MultiscannerModel",
    "MultiscannerBucket",
    "MultiscannerEndpoint",
}


def covered_labels(body: str) -> set[str]:
    """Labels a segment DOCUMENTS, not merely mentions.

    A bold `**Label**` is the document's definitional form, and it is used both
    for a top-level block and for a bullet inside a grouped section (the
    supply-chain sources list defines `**GithubRepository**` and
    `**SbomDocument**` that way). Matching only headings under-reports coverage
    and turns real documentation into phantom debt, which is worse than useless:
    it trains people to ignore the completeness test.

    Backticked mentions are deliberately NOT counted. Every relationship line
    names its endpoints in backticks, so counting them would mark a label
    documented because something points at it.
    """
    found = set(re.findall(r"\*\*([A-Z][A-Za-z0-9]*)\*\*", body))
    if "Asset nodes" in body:
        found |= GROUP_COVERAGE
    return found


def emit(segs: list[dict]) -> str:
    parts: list[str] = [
        '"""Addressable segments of the graph-schema document.',
        "",
        "GENERATED by tooling/scripts/seed_schema_catalog.py. Do not hand-edit the",
        "bodies here yet: until the renderer is the only consumer, the source of",
        "truth is still TEXT_TO_CYPHER_SYSTEM and this file is re-seeded from it.",
        "",
        "Bodies are VERBATIM slices. Concatenating SEGMENTS in order reproduces the",
        "source document byte-for-byte, which is what lets the renderer serve a",
        "subset without anyone having to trust that nothing was dropped.",
        '"""',
        "",
        "# The label-key declaration lives in schema_keys.py and is re-exported here",
        "# so every reader - the renderer, the tests, schema.py's constraint builder -",
        "# reaches ONE declaration rather than keeping a second list of labels.",
        "try:",
        "    from graph_db.schema_keys import KEY_CONSTRAINTS, LABELS_WITH_KEYS",
        "except ImportError:  # loaded by path, without the package",
        "    from schema_keys import KEY_CONSTRAINTS, LABELS_WITH_KEYS  # type: ignore",
        "",
        "__all__ = [",
        '    "SEGMENTS",',
        '    "LABELS",',
        '    "DOCUMENTED",',
        '    "RELATIONSHIP_TYPES",',
        '    "KEY_CONSTRAINTS",',
        '    "LABELS_WITH_KEYS",',
        '    "label_properties",',
        "]",
        "",
        "SEGMENTS = [",
    ]
    for s in segs:
        parts.append("    {")
        parts.append(f'        "kind": {s["kind"]!r},')
        parts.append(f'        "key": {s["key"]!r},')
        parts.append(f'        "section": {s["section"]!r},')
        parts.append(f'        "documents": {sorted(covered_labels(s["body"]))!r},')
        if "Relationships" in s["section"] and s["kind"] != "LABEL":
            rels = parse_relationship_block(s["body"])
            parts.append(f'        "relationships": {rels["relationships"]!r},')
        if s["kind"] == "LABEL":
            fields = parse_label_block(s["body"], s["key"])
            parts.append(f'        "description": {fields["description"]!r},')
            parts.append(f'        "groups": {fields["groups"]!r},')
            parts.append(f'        "relationships": {fields["relationships"]!r},')
            parts.append(f'        "subtypes": {fields["subtypes"]!r},')
            parts.append(f'        "notes": {fields["notes"]!r},')
        parts.append('        "body": """' + s["body"] + '""",')
        parts.append("    },")
    parts.append("]")
    parts.append("")
    parts.append("#: label -> the segment whose heading defines it (per-label rendering).")
    parts.append("LABELS = {s[\"key\"]: s for s in SEGMENTS if s[\"kind\"] == \"LABEL\"}")
    parts.append("")
    parts.append("#: every label the document DOCUMENTS, including those defined inside a")
    parts.append("#: grouped block rather than under their own heading. This is what the")
    parts.append("#: completeness test measures against graph_db/schema.py.")
    parts.append("DOCUMENTED = {lab for s in SEGMENTS for lab in s[\"documents\"]}")
    parts.append("")
    parts.append("#: Every relationship TYPE the document describes, from the relationship")
    parts.append("#: sections and from edges written inside a label block.")
    parts.append("RELATIONSHIP_TYPES = {")
    parts.append("    r[\"type\"] for s in SEGMENTS for r in s.get(\"relationships\", [])")
    parts.append("}")
    parts.append("")
    parts.append("")
    parts.append("def label_properties(label):")
    parts.append('    """{name: {type, desc, group}} for one label, flattened across groups."""')
    parts.append("    seg = LABELS.get(label)")
    parts.append("    if not seg:")
    parts.append("        return {}")
    parts.append("    out = {}")
    parts.append("    for g in seg[\"groups\"]:")
    parts.append("        for p in g[\"properties\"]:")
    parts.append("            out.setdefault(p[\"name\"], {**p, \"group\": g[\"header\"]})")
    parts.append("    return out")
    parts.append("")
    return "\n".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify only, do not write")
    args = ap.parse_args()

    doc = extract_prompt()
    segs = segment(doc)

    rebuilt = "".join(s["body"] for s in segs)
    if rebuilt != doc:
        print("FAIL: segmentation is lossy; refusing to write", file=sys.stderr)
        return 1

    # Bodies are emitted as triple-quoted Python literals, so a backslash becomes
    # an escape sequence. A markdown table escape (`\|`) copied into the source
    # silently turned into an invalid-escape SyntaxWarning on every import of the
    # generated catalog. Refuse rather than emit code that warns.
    if "\\" in doc:
        bad = [ln for ln in doc.split("\n") if "\\" in ln][:3]
        print("FAIL: the source contains a backslash, which does not survive as a",
              file=sys.stderr)
        print("      Python string literal. Remove it (markdown escapes are not",
              file=sys.stderr)
        print("      needed outside a table):", file=sys.stderr)
        for ln in bad:
            print(f"        {ln.strip()[:100]}", file=sys.stderr)
        return 1

    sha = hashlib.sha1(doc.encode()).hexdigest()
    n_labels = sum(1 for s in segs if s["kind"] == "LABEL")
    print(f"source     : {len(doc)} chars, sha1 {sha}")
    print(f"segments   : {len(segs)} ({n_labels} labels)")
    print("round-trip : byte-identical")

    if FIXTURE.exists():
        fx = FIXTURE.read_text(encoding="utf-8")
        print(f"fixture    : {'MATCHES' if fx == doc else 'DIFFERS (update the fixture deliberately)'}")

    if args.check:
        return 0

    OUT.write_text(emit(segs), encoding="utf-8")
    print(f"wrote      : {OUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
