"""One RESOLVES_TO edge per Subdomain -> IP pair, whichever tool reports it.

A relationship MERGE matches on every property in its pattern, so
``MERGE (s)-[:RESOLVES_TO {record_type: 'A'}]->(i)`` does not see an edge a
plain ``MERGE (s)-[:RESOLVES_TO]->(i)`` wrote, and neither sees one tagged
``{discovered_via: 'vhost_sni_enum'}``. Each writer that spelled the pattern
differently added a parallel edge for the same DNS fact. The writers now MERGE
the bare pattern and SET the properties afterwards (a static test keeps it that
way); ``consolidate_resolves_to_identity`` in schema.py folds the edges stored
before that, once per database.

Folding keeps the union of the parallel edges' properties rather than one
edge's: OTX's passive-DNS ``first_seen``/``last_seen`` are the only history of
when a name pointed at an address, and they usually sit on a different edge
from the one DNS resolution wrote.

No imports from graph_db: schema.py loads this during package initialisation.
"""


# The earliest value wins for these and the latest for the next set. Passive-DNS
# dates are ISO-8601 strings, which order correctly as strings.
_EARLIEST = ("timestamp", "first_seen")
_LATEST = ("last_seen_at", "last_seen")


def _present(value) -> bool:
    return value is not None and value != ""


def _pick(current, candidate, prefer_smaller: bool):
    if not _present(candidate):
        return current
    if not _present(current):
        return candidate
    try:
        smaller = candidate < current
    except TypeError:
        # A string and a DateTime for one key: no order exists, keep the first.
        return current
    return candidate if smaller == prefer_smaller else current


def _record_type_for(ip_address) -> str:
    return "AAAA" if ":" in str(ip_address or "") else "A"


def merge_edge_properties(edges: list, ip_address: str = None) -> dict:
    """The properties one edge must carry to replace all of ``edges``.

    ``edges`` is the list of property maps in a stable order; a key with no
    rule keeps its first present value. ``record_type`` can disagree only where
    a reverse-DNS writer hard-coded 'A' for an IPv6 address, so a conflict is
    settled by the address family.
    """
    merged = {}
    for props in edges:
        for key, value in (props or {}).items():
            if key in _EARLIEST:
                merged[key] = _pick(merged.get(key), value, prefer_smaller=True)
            elif key in _LATEST:
                merged[key] = _pick(merged.get(key), value, prefer_smaller=False)
            elif not _present(merged.get(key)) and _present(value):
                merged[key] = value
            elif key not in merged:
                merged[key] = value

    record_types = {p.get("record_type") for p in edges if _present((p or {}).get("record_type"))}
    if len(record_types) > 1 and ip_address:
        merged["record_type"] = _record_type_for(ip_address)
    return {k: v for k, v in merged.items() if v is not None}


def fold_resolves_to_duplicates(session, user_id: str = None, project_id: str = None,
                                batch: int = 1_000) -> dict:
    """Fold every group of parallel RESOLVES_TO edges; one project, or all.

    A group is the edges between one Subdomain and one IP, so it can never span
    projects. The first edge survives carrying the merged properties and the
    rest are deleted; no node is touched. Idempotent: a folded pair is no longer
    a group.
    """
    scope = dict(uid=user_id, pid=project_id)
    folded = pairs = 0
    while True:
        groups = session.run(
            """
            MATCH (s:Subdomain)-[r:RESOLVES_TO]->(i:IP)
            WHERE ($uid IS NULL OR s.user_id = $uid)
              AND ($pid IS NULL OR s.project_id = $pid)
            WITH s, i, r ORDER BY elementId(r)
            WITH s, i, collect(r) AS rels
            WHERE size(rels) > 1
            WITH i, rels LIMIT $batch
            RETURN i.address AS address,
                   [r IN rels | elementId(r)] AS ids,
                   [r IN rels | properties(r)] AS props
            """,
            batch=int(batch), **scope,
        ).data()
        if not groups:
            break

        work = [{"keep": g["ids"][0], "extras": g["ids"][1:],
                 "props": merge_edge_properties(g["props"], g["address"])}
                for g in groups]
        row = session.run(
            """
            UNWIND $work AS w
            MATCH ()-[k:RESOLVES_TO]->() WHERE elementId(k) = w.keep
            SET k = w.props
            WITH w
            UNWIND w.extras AS extra
            MATCH ()-[x:RESOLVES_TO]->() WHERE elementId(x) = extra
            DELETE x
            RETURN count(*) AS c
            """,
            work=work,
        ).single()
        deleted = (row or {}).get("c") or 0
        if not deleted:
            # Nothing deleted means the next round would read the same groups.
            raise RuntimeError(f"RESOLVES_TO fold made no progress on {len(work)} pair(s)")
        folded += deleted
        pairs += len(work)
    return {"folded": folded, "pairs": pairs}
