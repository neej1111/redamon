"""One Technology node per product and version, whichever scanner reports it.

Technology identity is ``(name, version, user_id, project_id)``, and the
uniqueness constraint on it is case-sensitive and ignores a node whose version
is NULL. Scanners disagree on both: httpx and Wappalyzer spell the same product
differently ("Amazon CloudFront" / "Amazon Cloudfront"), and a detector that
cannot read a version stores ``''`` while an older write path stored nothing.
Each disagreement used to produce a second node, splitting the product's edges
between the two.

The writers resolve the name and version through this module BEFORE they MERGE,
so a new detection lands on the node that already exists.
``consolidate_technology_identity`` in schema.py folds the duplicates written
before that, once per database.

Folding one node into another keeps every edge with its properties and unions
``detected_by``. Both matter to ``clear_gvm_data``: it deletes Technology nodes
whose ``detected_by`` is exactly ``'gvm'`` and USES_TECHNOLOGY edges whose
``detected_by`` is ``'gvm'``, so a fold that kept only one side's provenance
would let a GVM rescan delete what httpx or nmap found.

No imports from graph_db: schema.py loads this during package initialisation.
"""


#: Every relationship type a Technology node can carry, and which way it points
#: relative to the Technology. Folding moves each of these; a node still holding
#: any other type is kept rather than deleted.
#:
#: USES_TECHNOLOGY       (Endpoint|Service|Port|IP|BaseURL) -> Technology
#: HAS_TECHNOLOGY        (Port|IP|Parameter)                -> Technology
#: FOUND_ON              Vulnerability -> Technology   (nmap NSE)
#: FINDING_AFFECTS_TECH  ChainFinding  -> Technology   (agent)
#: STEP_IDENTIFIED       ChainStep     -> Technology   (agent)
#: HAS_KNOWN_CVE         Technology -> CVE
#: HAS_VULNERABILITY     Technology -> Vulnerability   (GVM)
TECH_RELATIONSHIPS = (
    ("USES_TECHNOLOGY", "in"),
    ("HAS_TECHNOLOGY", "in"),
    ("FOUND_ON", "in"),
    ("FINDING_AFFECTS_TECH", "in"),
    ("STEP_IDENTIFIED", "in"),
    ("HAS_KNOWN_CVE", "out"),
    ("HAS_VULNERABILITY", "out"),
)


def tech_name_key(name) -> str:
    """The comparison key two spellings of one product share."""
    return (name or "").strip().lower()


def resolve_tech_name(session, name: str, user_id: str, project_id: str) -> str:
    """Return the spelling to MERGE a Technology on.

    An exact match wins; otherwise the best-connected spelling already in this
    project does. A product seen for the first time keeps the name it came with.
    """
    if not name:
        return name
    rec = session.run(
        """
        MATCH (t:Technology {user_id: $uid, project_id: $pid})
        WHERE toLower(trim(t.name)) = $key
        RETURN t.name AS name
        ORDER BY t.name = $name DESC, COUNT { (t)--() } DESC, t.name
        LIMIT 1
        """,
        key=tech_name_key(name), name=name, uid=user_id, pid=project_id,
    ).single()
    return rec["name"] if rec and rec["name"] else name


def resolve_tech_version(session, name: str, version: str,
                         user_id: str, project_id: str) -> str:
    """Return the version to MERGE a Technology node on, collapsing duplicates.

    A versionless detection is stored with ``version: ''`` (Neo4j cannot MERGE
    on null), so two detectors disagreeing about whether they can read a
    version produced TWO nodes for one technology - observed live as React
    ``18.2.0`` (httpx) alongside React ``''`` (wappalyzer).

    Both directions are handled:
      - a versionless detection arrives and a versioned node already exists
        -> reuse the versioned node, do not create the '' twin
      - a versioned detection arrives and a versionless node exists
        -> fold the twin into the versioned node

    Returns the version string the caller should MERGE on.
    """
    if version:
        session.run(
            """
            MERGE (new:Technology {name: $name, version: $version,
                                   user_id: $uid, project_id: $pid})
            SET new.updated_at = datetime()
            """,
            name=name, version=version, uid=user_id, pid=project_id,
        )
        ids = session.run(
            """
            MATCH (old:Technology {name: $name, version: '',
                                   user_id: $uid, project_id: $pid})
            MATCH (new:Technology {name: $name, version: $version,
                                   user_id: $uid, project_id: $pid})
            RETURN elementId(old) AS old_id, elementId(new) AS new_id
            """,
            name=name, version=version, uid=user_id, pid=project_id,
        ).single()
        if ids:
            absorb_technology(session, ids["old_id"], ids["new_id"],
                              user_id, project_id, label=name)
        return version

    rec = session.run(
        """
        MATCH (t:Technology {name: $name, user_id: $uid, project_id: $pid})
        WHERE t.version <> ''
        RETURN t.version AS version
        ORDER BY t.version DESC
        LIMIT 1
        """,
        name=name, uid=user_id, pid=project_id,
    ).single()
    return rec["version"] if rec and rec["version"] else ""


def _edge_patterns(rel: str, direction: str):
    if direction == "in":
        return (f"(other)-[r:`{rel}`]->(old)",
                f"(other)-[x:`{rel}`]->(new)",
                f"(other)-[n:`{rel}`]->(new)")
    return (f"(old)-[r:`{rel}`]->(other)",
            f"(new)-[x:`{rel}`]->(other)",
            f"(new)-[n:`{rel}`]->(other)")


# `old` and `new` are addressed by elementId because two NULL-version nodes with
# the same name are both legal, so the natural key cannot tell them apart. The
# tenant keys stay on the pattern so an id can never reach another project.
_PAIR = """
    MATCH (old:Technology {user_id: $uid, project_id: $pid}) WHERE elementId(old) = $old_id
    MATCH (new:Technology {user_id: $uid, project_id: $pid}) WHERE elementId(new) = $new_id
"""


def absorb_technology(session, old_id: str, new_id: str, user_id: str,
                      project_id: str, label: str = "") -> bool:
    """Fold Technology ``old`` into ``new``; True when ``old`` was deleted.

    Each edge moves with its properties. When ``new`` already has the same edge
    with the same properties the moved one is dropped; with different
    properties both are kept, because ``detected_by`` on an edge is what
    ``clear_gvm_data`` decides by. ``new`` keeps its own name, version and
    ``updated_at`` (a fold is not a sighting, and bumping it would light the
    unseen-rows badge); properties only ``old`` has are copied over.
    """
    params = dict(old_id=old_id, new_id=new_id, uid=user_id, pid=project_id)
    for rel, direction in TECH_RELATIONSHIPS:
        edge, twin, moved = _edge_patterns(rel, direction)
        # DELETE r is not optional: an edge left on `old` keeps it alive under
        # the empty-node guard below, for ever.
        session.run(
            f"""{_PAIR}
            MATCH {edge}
            WITH old, new, other, r, properties(r) AS props
            FOREACH (_ IN CASE WHEN EXISTS {{ MATCH {twin} WHERE properties(x) = props }}
                               THEN [] ELSE [1] END |
                CREATE {moved} SET n = props)
            DELETE r
            """,
            **params,
        )

    # `gvm` goes last so clear_gvm_data's `replace(detected_by, ',gvm', '')`
    # strips it and leaves the other scanners' names behind.
    session.run(
        f"""{_PAIR}
        WITH old, new, properties(new) AS kept,
             [s IN split(coalesce(new.detected_by, '') + ',' + coalesce(old.detected_by, ''), ',')
              WHERE trim(s) <> '' | trim(s)] AS parts
        WITH old, new, kept, old.name AS old_name, old.version AS old_version,
             reduce(acc = [], s IN parts | CASE WHEN s IN acc THEN acc ELSE acc + s END) AS seen
        // The constraint is checked per write, so `old`'s key must not pass
        // through `new` on the way: lift it off, copy, then put it back.
        REMOVE old.name, old.version
        SET new += properties(old)
        SET new += kept
        SET old.name = old_name, old.version = old_version
        SET new.version = kept.version,
            new.detected_by = CASE WHEN size(seen) = 0 THEN NULL ELSE
                reduce(out = '', s IN [d IN seen WHERE d <> 'gvm'] + [d IN seen WHERE d = 'gvm'] |
                       CASE WHEN out = '' THEN s ELSE out + ',' + s END) END,
            new.confidence = CASE
                WHEN old.confidence IS NULL THEN kept.confidence
                WHEN kept.confidence IS NULL OR old.confidence > kept.confidence THEN old.confidence
                ELSE kept.confidence END
        """,
        **params,
    )

    # Delete only once it holds nothing: a relationship type TECH_RELATIONSHIPS
    # does not know would otherwise vanish with no trace, and a leftover
    # duplicate node is the far cheaper failure.
    record = session.run(
        f"""
        MATCH (old:Technology {{user_id: $uid, project_id: $pid}}) WHERE elementId(old) = $old_id
          AND NOT (old)--()
        DELETE old
        RETURN count(old) AS absorbed
        """,
        **params,
    ).single()
    if record is not None and record["absorbed"]:
        return True

    leftover = session.run(
        """
        MATCH (old:Technology {user_id: $uid, project_id: $pid})-[r]-()
        WHERE elementId(old) = $old_id
        RETURN collect(DISTINCT type(r)) AS types
        """,
        **params,
    ).single()
    if leftover and leftover["types"]:
        print(f"[!][graph-db] duplicate Technology {label!r} kept: unmoved "
              f"relationship type(s) {leftover['types']} - add them to "
              f"TECH_RELATIONSHIPS")
    return False


def fold_technology_duplicates(session, user_id: str = None, project_id: str = None,
                               batch: int = 10_000) -> dict:
    """Fold every group of duplicate Technology nodes; one project, or all.

    A group is one project's nodes whose names differ only in case or
    surrounding spaces and whose versions are equal once NULL counts as ''.
    The survivor is the best-connected node, preferring one that HAS a version
    so the NULL half is folded away. Groups never span projects: the tenant
    keys are part of the grouping, and absorb_technology re-checks them.

    Afterwards a NULL version left on a node with no '' twin becomes ''. That
    runs second so it cannot collide with a twin still waiting to be folded.
    """
    scope = dict(uid=user_id, pid=project_id)
    groups = session.run(
        """
        MATCH (t:Technology)
        WHERE t.user_id IS NOT NULL AND t.project_id IS NOT NULL
          AND ($uid IS NULL OR t.user_id = $uid)
          AND ($pid IS NULL OR t.project_id = $pid)
          AND trim(coalesce(t.name, '')) <> ''
        WITH t, t.user_id AS uid, t.project_id AS pid,
             toLower(trim(t.name)) AS name_key, coalesce(t.version, '') AS version
        ORDER BY t.version IS NULL, COUNT { (t)--() } DESC, t.name
        WITH uid, pid, name_key, version, collect(elementId(t)) AS ids
        WHERE size(ids) > 1
        RETURN uid, pid, name_key, ids
        """,
        **scope,
    ).data()

    folded = 0
    for group in groups:
        survivor = group["ids"][0]
        for other in group["ids"][1:]:
            if absorb_technology(session, other, survivor, group["uid"], group["pid"],
                                 label=group["name_key"]):
                folded += 1

    versioned = 0
    while True:
        row = session.run(
            f"""
            MATCH (t:Technology)
            WHERE t.version IS NULL
              AND ($uid IS NULL OR t.user_id = $uid)
              AND ($pid IS NULL OR t.project_id = $pid)
              AND NOT EXISTS {{ MATCH (o:Technology {{name: t.name, version: '',
                                user_id: t.user_id, project_id: t.project_id}}) }}
            WITH t LIMIT {int(batch)}
            SET t.version = ''
            RETURN count(t) AS c
            """,
            **scope,
        ).single()
        touched = (row or {}).get("c") or 0
        versioned += touched
        if not touched:
            break
    return {"folded": folded, "versioned": versioned}
