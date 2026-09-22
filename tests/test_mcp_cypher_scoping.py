"""Strategy row 1 (L1): the hand-written MCP Cypher survives `scope_query`.

The inbound MCP analytics tools are the only place in the product where Cypher
is WRITTEN BY HAND in TypeScript and executed through the agent's tenant filter.
Nothing else connects those two: the TypeScript tests assert the query TEXT, and
the Python tests exercise `scope_query` against queries of their own. A change
to `graph_db/tenant_filter.py` can therefore break every analytics tool with no
test going red anywhere.

That gap is not hypothetical. The stale-exploit predicate in two of these
queries was in the wrong CLAUSE for a whole release: a TypeScript test asserted
the predicate was present, which it was, and passed while the query silently
dropped every CVE whose only exploit record was superseded.

What this pins, per the tenant filter's own rules:

  - the query is ACCEPTED rather than refused;
  - every tenant-owned pattern gets both tenant properties AND `!Muted`;
  - `CVE` and `MitreData` keep their global-reference exemption. This is the
    trap: those nodes carry no tenant properties by design, so a pattern that
    loses the exemption matches NOTHING and the view renders with its ranking
    silently gone;
  - nothing binds a parameter, because `/graph/exec` binds only the tenant pair;
  - nothing names the `Muted` label, which the filter refuses outright.

The queries are read out of the TypeScript source, because that is where they
actually live. A rename there fails this test loudly rather than leaving it
asserting nothing.
"""
import importlib.util
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ANALYTICS_TS = REPO / "webapp/src/lib/mcp/analyticsTools.ts"
LABELS_TS = REPO / "webapp/src/lib/mcp/findingLabels.ts"

_spec = importlib.util.spec_from_file_location(
    "tenant_filter", REPO / "graph_db/tenant_filter.py")
tf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tf)

#: Labels the filter never scopes, because they are shared reference data.
GLOBAL_LABELS = ("CVE", "MitreData", "Capec")

UID = "scoping-user"
PID = "scoping-project"


def _template_literal(source: str, name: str) -> str:
    """Pull `export const NAME = \\`...\\`` out of the TypeScript."""
    m = re.search(r"export const %s = `(.*?)`" % re.escape(name), source, re.S)
    assert m, f"{name} not found; it was renamed or removed"
    # `${TOP_N}` is the only interpolation in these queries.
    return re.sub(r"\$\{TOP_N\}", "50", m.group(1))


def _muteable_labels(source: str) -> list:
    m = re.search(r"MUTEABLE_FINDING_LABELS = Object\.freeze\(\[(.*?)\]\)", source, re.S)
    assert m, "MUTEABLE_FINDING_LABELS not found"
    return re.findall(r"'([A-Za-z]+)'", m.group(1))


def _stale_findings_cypher(labels: list) -> str:
    """Mirror of `staleFindingsCypher()`; the builder is three mechanical lines."""
    lines, carried = [], []
    for i, label in enumerate(labels):
        v = f"f{i}"
        prefix = (", ".join(carried) + ", ") if carried else ""
        lines.append(f"OPTIONAL MATCH ({v}:{label}) WHERE {v}.stale_since IS NOT NULL")
        lines.append(f"WITH {prefix}count({v}) AS c{i}")
        carried.append(f"c{i}")
    lines.append("RETURN " + " + ".join(carried) + " AS stale")
    return "\n".join(lines)


def _census_cypher(source: str) -> str:
    """Mirror of `attackSurfaceCypher()`, built from the CENSUS array itself.

    The builder is mechanical (chained OPTIONAL MATCH + WITH count), so the only
    thing worth reading out of the TypeScript is the entries. Adjacent quoted
    strings joined by `+` are concatenated the way TypeScript would.
    """
    m = re.search(r"const CENSUS: CensusEntry\[\] = \[(.*?)\n\]", source, re.S)
    assert m, "CENSUS not found"
    body = m.group(1)

    entries = []
    for raw in re.findall(r"\{(.*?)\}", body, re.S):
        key = re.search(r"key:\s*'([^']+)'", raw)
        pattern = re.search(r"pattern:\s*'([^']+)'", raw)
        assert key and pattern, raw
        where_m = re.search(r"where:\s*(.*?),?\s*$", raw, re.S)
        where = None
        if where_m and where_m.group(1).strip().startswith(('"', "'")):
            # Join the string literals a `+` concatenation is made of.
            parts = re.findall(r'"([^"]*)"|\'([^\']*)\'', where_m.group(1))
            where = "".join(a or b for a, b in parts)
        entries.append((key.group(1), pattern.group(1), where))

    assert len(entries) >= 15, f"only {len(entries)} census entries extracted"

    lines, carried = [], []
    for key, pattern, where in entries:
        variable = pattern.split(":")[0]
        prefix = (", ".join(carried) + ", ") if carried else ""
        lines.append(f"OPTIONAL MATCH ({pattern})" + (f" WHERE {where}" if where else ""))
        lines.append(f"WITH {prefix}count({variable}) AS {key}")
        carried.append(key)
    lines.append("RETURN " + ", ".join(carried))
    return "\n".join(lines)


def _queries() -> dict:
    analytics = ANALYTICS_TS.read_text()
    labels = _muteable_labels(LABELS_TS.read_text())
    return {
        "exploit_paths": _template_literal(analytics, "EXPLOIT_PATHS_CYPHER"),
        "blast_radius": _template_literal(analytics, "BLAST_RADIUS_CYPHER"),
        "attack_surface": _census_cypher(analytics),
        "stale_findings": _stale_findings_cypher(labels),
    }


class McpCypherScopingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.queries = _queries()

    def test_the_extracted_census_matches_the_builder(self):
        # The census is BUILT rather than written, so this reconstruction is the
        # one place drift can hide. Pin the shape and a few keys: if the builder
        # changes, this fails loudly instead of testing a query nobody ships.
        q = self.queries["attack_surface"]
        for key in ("subdomains", "criticalVulnerabilities", "knownExploits"):
            self.assertIn(f"AS {key}", q)
        self.assertTrue(q.startswith("OPTIONAL MATCH (a0:Subdomain)"))
        self.assertIn("b7.stale_since IS NULL", q)
        self.assertEqual(q.count("OPTIONAL MATCH"), q.count("WITH "))

    def test_the_typescript_source_is_actually_readable(self):
        # Guards the whole file: a rename would otherwise make every assertion
        # below vacuous.
        self.assertTrue(ANALYTICS_TS.exists(), ANALYTICS_TS)
        for name, q in self.queries.items():
            self.assertIn("MATCH", q, name)

    def test_every_query_is_accepted_by_the_tenant_filter(self):
        for name, q in self.queries.items():
            with self.subTest(query=name):
                try:
                    tf.scope_query(q, UID, PID)
                except Exception as e:  # noqa: BLE001 - any refusal is a failure
                    self.fail(f"{name} refused by scope_query: {type(e).__name__}: {e}")

    def test_every_query_has_a_labelled_pattern(self):
        # A query with none is hard-rejected: it cannot be proven scoped. A
        # census is exactly that shape, which is why each one carries a label.
        for name, q in self.queries.items():
            with self.subTest(query=name):
                self.assertTrue(tf.has_labelled_node_pattern(q))

    def test_tenant_owned_patterns_are_scoped_and_mute_filtered(self):
        for name, q in self.queries.items():
            scoped = tf.scope_query(q, UID, PID)
            for label in ("Technology", "BaseURL", "Service", "Port", "ExploitGvm",
                          "Vulnerability", "Secret", "JsReconFinding"):
                if f":{label})" not in q and f":{label} " not in q:
                    continue
                with self.subTest(query=name, label=label):
                    self.assertIn(f"{label}&!Muted", scoped)
                    self.assertIn("user_id: $tenant_user_id", scoped)
                    self.assertIn("project_id: $tenant_project_id", scoped)

    def test_GLOBAL_reference_labels_keep_their_exemption(self):
        # THE TRAP. CVE and MitreData carry no tenant properties, so a pattern
        # that loses the exemption matches nothing: the KEV signal goes
        # permanently false and the CWE columns permanently null, with a 200 and
        # a rendered view to show for it.
        for name, q in self.queries.items():
            scoped = tf.scope_query(q, UID, PID)
            for label in GLOBAL_LABELS:
                with self.subTest(query=name, label=label):
                    self.assertNotIn(f"{label}&!Muted", scoped)
                    self.assertNotIn(f"({label} {{user_id:", scoped)

    def test_a_global_node_is_never_re_referenced_without_its_label(self):
        # The shape that loses the exemption. `(c)` inherits injection; `(c:CVE)`
        # does not.
        for name, q in self.queries.items():
            with self.subTest(query=name):
                self.assertEqual(re.findall(r"\((c|m|cap)\)", q), [])

    def test_nothing_binds_a_parameter_the_endpoint_cannot_supply(self):
        # GraphExecRequest has no params field: the cypher branch binds exactly
        # the tenant pair. A carried-over `$pid` dies on ParameterMissing, and
        # injection first turns an inline tenant property into a duplicated map
        # key.
        for name, q in self.queries.items():
            with self.subTest(query=name):
                self.assertEqual(re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", q), [])

    def test_nothing_names_the_reserved_label(self):
        # `scope_query` refuses any query that mentions it, which is why the
        # `notMuted()` helper every browser-side query uses cannot be used here.
        for name, q in self.queries.items():
            with self.subTest(query=name):
                self.assertFalse(tf.names_muted_label(q))

    def test_the_stale_predicate_sits_on_its_own_match(self):
        # Placement, not presence. On a `WITH`, the predicate drops the ROW and
        # the row carries the CVE.
        for name, q in self.queries.items():
            for line in q.splitlines():
                if "stale_since" not in line:
                    continue
                with self.subTest(query=name, line=line.strip()[:60]):
                    self.assertTrue(line.lstrip().startswith("OPTIONAL MATCH "))


if __name__ == "__main__":
    unittest.main()
