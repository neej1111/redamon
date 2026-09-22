"""Absorbing a versionless Technology twin must not drop its relationships.

Technology identity is (name, version, tenant), and a detector that cannot read
a version stores `version: ''`. When a versioned detection arrives it absorbs
that twin. The absorb re-parented USES_TECHNOLOGY and then DETACH DELETEd, so
every OTHER edge on the twin went with it — and the port scan, which reports
versionless services, normally runs BEFORE the HTTP probe that supplies a
version, so the twin usually does hold `(Port)-[:HAS_TECHNOLOGY]->` by then.
A moved edge must also keep its properties: clear_gvm_data decides by
`detected_by` on the edge. tests/test_technology_identity_graph_live.py proves
the same against a real database.

Run: python -m unittest tests.test_technology_twin_absorption
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.recon.http_mixin import (  # noqa: E402
    _TECH_TWIN_RELATIONSHIPS, resolve_tech_version,
)


class FakeResult:
    def __init__(self, single=None):
        self._single = single

    def single(self):
        return self._single


class FakeSession:
    """`absorbed` decides whether the zero-degree delete claims the twin."""

    def __init__(self, absorbed=1, leftover_types=None):
        self.queries = []
        self.absorbed = absorbed
        self.leftover_types = leftover_types or []

    def run(self, query, **kwargs):
        self.queries.append((query, kwargs))
        if "AS old_id" in query:
            return FakeResult({"old_id": "4:db:1", "new_id": "4:db:2"})
        if "AS absorbed" in query:
            return FakeResult({"absorbed": self.absorbed})
        if "AS types" in query:
            return FakeResult({"types": self.leftover_types})
        if "AS version" in query:
            return FakeResult(None)
        return FakeResult()


def _absorb(**kwargs):
    session = FakeSession(**kwargs)
    result = resolve_tech_version(session, "nginx", "1.24.0", "u1", "p1")
    return session, result


class TestEveryRelationshipMoves(unittest.TestCase):
    def test_the_inventory_covers_every_type_a_technology_can_carry(self):
        self.assertEqual(
            {rel for rel, _ in _TECH_TWIN_RELATIONSHIPS},
            {"USES_TECHNOLOGY", "HAS_TECHNOLOGY", "FOUND_ON", "FINDING_AFFECTS_TECH",
             "STEP_IDENTIFIED", "HAS_KNOWN_CVE", "HAS_VULNERABILITY"},
        )

    def test_each_type_gets_its_own_reparenting_query(self):
        session, _ = _absorb()
        joined = "\n".join(q for q, _ in session.queries)
        for rel, _direction in _TECH_TWIN_RELATIONSHIPS:
            self.assertIn(f"[n:`{rel}`]", joined, f"{rel} is never moved")

    def test_direction_is_respected(self):
        # An inbound edge re-created outbound would reverse the graph.
        session, _ = _absorb()
        joined = "\n".join(q for q, _ in session.queries)
        self.assertIn("CREATE (other)-[n:`HAS_TECHNOLOGY`]->(new)", joined)
        self.assertIn("CREATE (new)-[n:`HAS_KNOWN_CVE`]->(other)", joined)

    def test_a_moved_edge_keeps_its_properties(self):
        session, _ = _absorb()
        moves = [q for q, _ in session.queries if "CREATE (" in q]
        self.assertEqual(len(moves), len(_TECH_TWIN_RELATIONSHIPS))
        for query in moves:
            self.assertIn("SET n = props", query)
            self.assertIn("properties(x) = props", query,
                          "an identical edge already on `new` must not be duplicated")

    def test_the_twin_is_deleted_only_once_it_holds_nothing(self):
        session, _ = _absorb()
        deletes = [q for q, _ in session.queries if "DELETE old" in q]
        self.assertEqual(len(deletes), 1)
        self.assertIn("NOT (old)--()", deletes[0])
        self.assertNotIn("DETACH DELETE", deletes[0],
                         "DETACH is what silently dropped the edges")

    def test_a_twin_holding_an_unknown_relationship_is_kept_not_destroyed(self):
        # A relationship type the inventory does not know about must cost a
        # duplicate node, never the edge.
        session, _ = _absorb(absorbed=0, leftover_types=["SOME_NEW_REL"])
        types_query = [q for q, _ in session.queries if "AS types" in q]
        self.assertEqual(len(types_query), 1,
                         "an unabsorbed twin must be reported, not ignored")

    def test_the_resolved_version_is_still_returned(self):
        _, version = _absorb()
        self.assertEqual(version, "1.24.0")

    def test_a_versionless_detection_does_not_absorb_anything(self):
        session = FakeSession()
        resolve_tech_version(session, "nginx", "", "u1", "p1")
        self.assertFalse([q for q, _ in session.queries if "DELETE" in q])


class TestTenantScoping(unittest.TestCase):
    def test_every_absorb_query_names_both_tenant_keys(self):
        session, _ = _absorb()
        for query, params in session.queries:
            if "Technology" not in query:
                continue
            self.assertIn("user_id: $uid", query)
            self.assertIn("project_id: $pid", query)
            self.assertEqual(params["uid"], "u1")
            self.assertEqual(params["pid"], "p1")


if __name__ == "__main__":
    unittest.main()
