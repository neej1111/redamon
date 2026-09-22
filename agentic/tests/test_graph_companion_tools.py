"""The agent's graph_schema and graph_summary tools.

The MCP surface and the agent surface are deliberately IDENTICAL: same three
tools, same descriptions, same usage rule. One mental model, one set of tests.

What is pinned here is the behaviour that makes graph_summary worth having: a
read failure must be a plain failure, never an empty summary, because an empty
summary reads as "nothing has ever been scanned" - a false negative in a
security tool. And an EMPTY graph must say so in those words, so the agent does
not report "not found" when the truth is "not looked for".
"""
import os
import sys
import unittest


_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

import tools as tools_mod  # noqa: E402
from tools import Neo4jToolManager  # noqa: E402


class _FakeGraph:
    def __init__(self, nodes=None, rels=None, raises=False):
        self._nodes = nodes if nodes is not None else []
        self._rels = rels if rels is not None else []
        self.raises = raises
        self.queries = []
        self.params = []

    def query(self, cypher, params=None):
        if self.raises:
            raise RuntimeError("neo4j unreachable")
        self.queries.append(cypher)
        self.params.append(params)
        return self._rels if "type(r)" in cypher else self._nodes


def _manager(graph):
    m = Neo4jToolManager.__new__(Neo4jToolManager)
    m.uri, m.user, m.password = "bolt://x", "neo4j", "pw"
    m.graph = graph
    return m


class _tenant:
    """Set the request-scoped tenant contextvars the tools read, then restore.

    A ContextVar's `get` is read-only, so this sets real values and resets the
    tokens afterwards rather than patching the attribute.
    """

    def __init__(self, user_id="u1", project_id="p1"):
        self.user_id, self.project_id = user_id, project_id

    def __enter__(self):
        self._u = tools_mod.current_user_id.set(self.user_id)
        self._p = tools_mod.current_project_id.set(self.project_id)
        return self

    def __exit__(self, *exc):
        tools_mod.current_user_id.reset(self._u)
        tools_mod.current_project_id.reset(self._p)
        return False


async def _call(tool):
    return await tool.ainvoke({})


class GraphSchemaToolTests(unittest.IsolatedAsyncioTestCase):
    async def test_it_serves_the_generator_prompt_content(self):
        """The schema served is the composed document: the invariant rules from
        TEXT_TO_CYPHER_SYSTEM with the generated schema spliced in at the marker.

        Asserting equality with TEXT_TO_CYPHER_SYSTEM alone was right while that
        constant held the node blocks; it no longer does, and comparing against
        it would now pass only if the schema had gone missing.
        """
        from graph_schema_prompt import build_schema_document

        out = await _call(_manager(None).get_schema_tool())
        self.assertEqual(out, build_schema_document())

    async def test_it_needs_no_database(self):
        # The one graph tool that still answers when Neo4j is down.
        out = await _call(_manager(_FakeGraph(raises=True)).get_schema_tool())
        self.assertGreater(len(out), 2000)

    async def test_it_takes_no_arguments(self):
        tool = _manager(None).get_schema_tool()
        self.assertEqual(tool.name, "graph_schema")

    async def test_its_docstring_carries_the_usage_rule(self):
        tool = _manager(None).get_schema_tool()
        self.assertIn("Use graph_summary first", tool.description)
        self.assertIn("Use graph_schema when", tool.description)


class GraphSummaryToolTests(unittest.IsolatedAsyncioTestCase):
    async def test_it_reports_counts_per_label(self):
        graph = _FakeGraph(
            nodes=[{"label": "IP", "count": 12}, {"label": "Subdomain", "count": 40}],
            rels=[{"type": "RESOLVES_TO", "count": 8}],
        )
        with _tenant():
            out = await _call(_manager(graph).get_summary_tool())

        self.assertIn("IP: 12", out)
        self.assertIn("Subdomain: 40", out)
        self.assertIn("RESOLVES_TO: 8", out)

    async def test_it_returns_COUNTS_only_never_sample_values(self):
        # Sample values are live target data and would leak recon output into
        # the model's context ahead of any deliberate query.
        graph = _FakeGraph(nodes=[{"label": "Secret", "count": 3}])
        with _tenant():
            out = await _call(_manager(graph).get_summary_tool())

        self.assertIn("Secret: 3", out)
        for cypher in graph.queries:
            # Only label/type and a count are ever projected.
            self.assertNotIn("RETURN n\n", cypher)
            self.assertTrue("count(*)" in cypher)

    async def test_the_query_carries_the_FULL_tenant_key(self):
        graph = _FakeGraph(nodes=[{"label": "IP", "count": 1}])
        with _tenant("userA", "projB"):
            await _call(_manager(graph).get_summary_tool())

        for cypher in graph.queries:
            self.assertIn("$tenant_user_id", cypher)
            self.assertIn("$tenant_project_id", cypher)
        for params in graph.params:
            self.assertEqual(params["tenant_user_id"], "userA")
            self.assertEqual(params["tenant_project_id"], "projB")

    async def test_muted_and_stale_findings_are_excluded(self):
        # Counting a suppressed or resolved finding as live is the opposite of
        # what a census is read for.
        graph = _FakeGraph(nodes=[{"label": "IP", "count": 1}])
        with _tenant():
            await _call(_manager(graph).get_summary_tool())

        node_cypher = graph.queries[0]
        self.assertIn("NOT n:Muted", node_cypher)
        self.assertIn("stale_since IS NULL", node_cypher)

    async def test_an_EMPTY_graph_says_not_looked_for_not_not_present(self):
        with _tenant():
            out = await _call(_manager(_FakeGraph(nodes=[])).get_summary_tool())

        self.assertIn("EMPTY", out)
        self.assertIn("not looked for", out)

    async def test_a_read_failure_is_an_ERROR_never_an_empty_summary(self):
        with _tenant():
            out = await _call(_manager(_FakeGraph(raises=True)).get_summary_tool())

        self.assertTrue(out.startswith("Error"))
        # It must not be mistakable for "this project has nothing".
        self.assertNotIn("EMPTY", out)

    async def test_a_missing_tenant_refuses_rather_than_querying(self):
        graph = _FakeGraph(nodes=[{"label": "IP", "count": 1}])
        with _tenant("", ""):
            out = await _call(_manager(graph).get_summary_tool())

        self.assertIn("Missing user_id or project_id", out)
        self.assertEqual(graph.queries, [])

    async def test_its_docstring_carries_the_usage_rule(self):
        tool = _manager(None).get_summary_tool()
        self.assertEqual(tool.name, "graph_summary")
        self.assertIn("Use graph_summary first", tool.description)
        self.assertIn("never scanned", tool.description)


class ExecutorRegistrationTests(unittest.TestCase):
    """The companions must appear and disappear WITH query_graph."""

    def _executor(self, **kw):
        from tools import PhaseAwareToolExecutor

        return PhaseAwareToolExecutor(None, **kw)

    def test_all_three_register_together(self):
        ex = self._executor(
            graph_tool=lambda: None,
            graph_schema_tool=lambda: None,
            graph_summary_tool=lambda: None,
        )
        for name in ("query_graph", "graph_schema", "graph_summary"):
            self.assertIn(name, ex._all_tools)

    def test_no_graph_tool_means_no_companions(self):
        # get_tool() returns None when Neo4j setup fails. A companion offered
        # anyway would fail on every call instead of disappearing.
        ex = self._executor(
            graph_tool=None,
            graph_schema_tool=lambda: None,
            graph_summary_tool=lambda: None,
        )
        self.assertNotIn("query_graph", ex._all_tools)
        self.assertNotIn("graph_schema", ex._all_tools)
        self.assertNotIn("graph_summary", ex._all_tools)


if __name__ == "__main__":
    unittest.main()
