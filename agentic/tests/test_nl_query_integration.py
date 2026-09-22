"""L4 — the NL query path's tenant scoping against a REAL Neo4j.

`/graph/nl-query` runs LLM-generated Cypher. The unit tests mock the execution,
so they prove the plumbing and nothing about whether `scope_query`'s rewrite
actually isolates tenants once a real database executes it.

This runs the REAL `scope_query` output against a REAL graph holding TWO
tenants' data, for the query shapes an LLM plausibly emits - including the ones
that have historically bypassed the filter:

  * a bare `MATCH (n)` (the historical leak: it once bypassed injection entirely)
  * `OPTIONAL MATCH`, which supplies rows even when the pattern matches nothing
  * a relationship traversal, where only one endpoint might be scoped
  * `apoc.cypher.run`, which carried its query past injection as a string
    literal (the confirmed cross-tenant read this suite exists to keep closed)

The LLM is never invoked: the point is the scoping, not the generation.

Tier: integration; self-skips when Neo4j is unreachable.
"""
import os
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graph_db.tenant_filter import TenantScopeError, scope_query  # noqa: E402


def _connect():
    try:
        from neo4j import GraphDatabase
    except ImportError:
        return None
    auth = (
        os.environ.get("NEO4J_USER", "neo4j"),
        os.environ.get("NEO4J_PASSWORD", "password"),
    )
    uris = [u for u in (os.environ.get("NEO4J_URI"),) if u] + [
        "bolt://neo4j:7687", "bolt://localhost:7687", "bolt://host.docker.internal:7687",
    ]
    for uri in uris:
        try:
            driver = GraphDatabase.driver(uri, auth=auth, connection_timeout=3)
            driver.verify_connectivity()
            return driver
        except Exception:
            continue
    return None


_DRIVER = _connect()

MINE_U, MINE_P = f"nlu_{uuid.uuid4().hex[:8]}", f"nlp_{uuid.uuid4().hex[:8]}"
THEIRS_U, THEIRS_P = f"nlu_{uuid.uuid4().hex[:8]}", f"nlp_{uuid.uuid4().hex[:8]}"

SECRET = "THEIR-SECRET-VALUE-MUST-NOT-APPEAR"


@unittest.skipIf(_DRIVER is None, "Neo4j not reachable (integration tier)")
class NlQueryTenantIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with _DRIVER.session() as s:
            s.run(
                """
                CREATE (d:Domain {user_id:$u, project_id:$p, name:'mine.test'})
                CREATE (i:IP {user_id:$u, project_id:$p, address:'10.1.1.1'})
                CREATE (d)-[:RESOLVES_TO {user_id:$u, project_id:$p}]->(i)
                """,
                u=MINE_U, p=MINE_P,
            )
            s.run(
                """
                CREATE (d:Domain {user_id:$u, project_id:$p, name:'theirs.test'})
                CREATE (i:IP {user_id:$u, project_id:$p, address:'10.2.2.2'})
                CREATE (sec:Secret {user_id:$u, project_id:$p, value:$v})
                CREATE (d)-[:RESOLVES_TO {user_id:$u, project_id:$p}]->(i)
                """,
                u=THEIRS_U, p=THEIRS_P, v=SECRET,
            )

    @classmethod
    def tearDownClass(cls):
        if _DRIVER is None:
            return
        with _DRIVER.session() as s:
            for u, p in ((MINE_U, MINE_P), (THEIRS_U, THEIRS_P)):
                s.run(
                    "MATCH (n) WHERE n.user_id=$u AND n.project_id=$p DETACH DELETE n",
                    u=u, p=p,
                )
        _DRIVER.close()

    def _run_scoped(self, cypher, user_id=MINE_U, project_id=MINE_P):
        """Scope as production does, then execute. Returns the flattened text."""
        final = scope_query(cypher, user_id, project_id)
        with _DRIVER.session() as s:
            rows = list(
                s.run(
                    final,
                    {"tenant_user_id": user_id, "tenant_project_id": project_id},
                )
            )
        return rows, str(rows)

    def _assert_no_leak(self, blob):
        self.assertNotIn(SECRET, blob, "another tenant's SECRET value was returned")
        self.assertNotIn("theirs.test", blob, "another tenant's domain was returned")
        self.assertNotIn("10.2.2.2", blob, "another tenant's IP was returned")

    # --- query shapes an LLM plausibly emits ---------------------------------

    def test_a_labelled_read_returns_only_my_rows(self):
        rows, blob = self._run_scoped("MATCH (d:Domain) RETURN d.name AS name")
        self.assertIn("mine.test", blob)
        self._assert_no_leak(blob)

    def test_a_bare_MATCH_n_is_scoped_not_leaked(self):
        # The historical bug: `MATCH (n)` bypassed injection entirely and
        # returned another project's data.
        rows, blob = self._run_scoped("MATCH (n) RETURN n")
        self._assert_no_leak(blob)

    def test_OPTIONAL_MATCH_does_not_leak(self):
        # OPTIONAL MATCH yields a row even when the pattern matches nothing,
        # which is what made it useful as an anchor in the APOC bypass.
        rows, blob = self._run_scoped(
            "OPTIONAL MATCH (s:Secret) RETURN s.value AS v"
        )
        self._assert_no_leak(blob)

    def test_a_relationship_traversal_scopes_BOTH_endpoints(self):
        rows, blob = self._run_scoped(
            "MATCH (d:Domain)-[:RESOLVES_TO]->(i:IP) RETURN d.name AS d, i.address AS ip"
        )
        self.assertIn("mine.test", blob)
        self._assert_no_leak(blob)

    def test_a_UNION_scopes_every_arm(self):
        rows, blob = self._run_scoped(
            "MATCH (d:Domain) RETURN d.name AS v "
            "UNION MATCH (s:Secret) RETURN s.value AS v"
        )
        self._assert_no_leak(blob)

    def test_a_WHERE_clause_cannot_widen_the_scope(self):
        # An LLM asked for "everything" might try to defeat the filter in WHERE.
        rows, blob = self._run_scoped(
            "MATCH (s:Secret) WHERE s.value IS NOT NULL OR true RETURN s.value AS v"
        )
        self._assert_no_leak(blob)

    def test_the_other_tenant_sees_its_OWN_data(self):
        # The filter must isolate, not simply return nothing.
        rows, blob = self._run_scoped(
            "MATCH (s:Secret) RETURN s.value AS v", THEIRS_U, THEIRS_P
        )
        self.assertIn(SECRET, blob)

    def test_a_secret_query_from_MY_tenant_returns_nothing(self):
        rows, _ = self._run_scoped("MATCH (s:Secret) RETURN s.value AS v")
        self.assertEqual(rows, [], "my tenant has no Secret nodes")

    # --- the confirmed bypass stays closed, end to end -----------------------

    def test_apoc_cypher_run_is_refused_BEFORE_it_can_execute(self):
        # The confirmed live exploit. It must not reach the database at all.
        with self.assertRaises(TenantScopeError):
            self._run_scoped(
                "OPTIONAL MATCH (d:Domain) WITH d LIMIT 1 "
                'CALL apoc.cypher.run("MATCH (n:Secret) RETURN n.value AS v", {}) '
                "YIELD value RETURN value.v"
            )

    def test_apoc_cypher_runMany_write_is_refused(self):
        with self.assertRaises(TenantScopeError):
            self._run_scoped(
                "OPTIONAL MATCH (d:Domain) WITH d LIMIT 1 "
                'CALL apoc.cypher.runMany("CREATE (x:PwnMarker)", {}) '
                "YIELD result RETURN result"
            )
        # And nothing was written.
        with _DRIVER.session() as s:
            n = s.run("MATCH (x:PwnMarker) RETURN count(x) AS c").single()["c"]
        self.assertEqual(n, 0, "a write slipped through despite the refusal")

    def test_apoc_load_json_ssrf_is_refused(self):
        with self.assertRaises(TenantScopeError):
            self._run_scoped(
                'CALL apoc.load.json("http://169.254.169.254/latest/meta-data/") '
                "YIELD value RETURN value"
            )


if __name__ == "__main__":
    unittest.main()
