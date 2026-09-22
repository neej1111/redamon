"""VHost/SNI graph integrity, asserted against the statements the mixin runs.

A hidden virtual host proves that a server routes a Host header, never that DNS
resolves that name to that IP, so this module must not write RESOLVES_TO. It
must also leave no finding stranded: an in-scope candidate gets its Subdomain
(flagged unconfirmed), an out-of-scope one hangs off the IP that served it.

These run without Neo4j by driving the mixin against a session double that
records every statement and its parameters. The live counterparts, which prove
the same rules against a real database, are in
recon/tests/test_vhost_sni_graph.py.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graph_db.mixins.recon.vhost_sni_mixin import VhostSniMixin


class _Result:
    def __init__(self, row):
        self._row = row

    def single(self):
        return self._row


class _Session:
    """Answers the mixin's reads from an in-memory idea of the graph."""

    def __init__(self, subdomains=(), ips=(), domains=(), services=0, stale_edges=0):
        self.subdomains = set(subdomains)
        self.ips = set(ips)
        self.domains = set(domains)
        self.services = services
        self.stale_edges = stale_edges
        self.calls = []

    def run(self, query, **params):
        self.calls.append((" ".join(query.split()), params))
        if "DELETE r" in query:
            return _Result({"removed": self.stale_edges})
        if "MERGE (b:BaseURL" in query:
            linked = 1 if params.get("host") in self.subdomains else 0
            return _Result({"created": 1, "linked": linked})
        if "SERVES_URL" in query:
            return _Result({"matched": self.services})
        if "(d:Domain" in query:
            return _Result({"matched": 1 if params.get("domain") in self.domains else 0})
        if "MERGE (i)-[:HAS_VULNERABILITY]" in query or "SET i += $props" in query:
            return _Result({"matched": 1 if params.get("addr") in self.ips else 0})
        if "OPTIONAL MATCH (s:Subdomain" in query:
            return _Result({"matched": 1 if params.get("hostname") in self.subdomains else 0})
        return _Result({"matched": 0})

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Driver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class _Client(VhostSniMixin):
    def __init__(self, session):
        self.driver = _Driver(session)


def _finding(hostname, ip="192.0.2.20", ftype="hidden_vhost", layer="L7"):
    return {
        "id": f"vhost_sni_{hostname}_{ip}_443_{layer.lower()}",
        "hostname": hostname,
        "ip": ip,
        "port": 443,
        "scheme": "https",
        "layer": layer,
        "type": ftype,
        "severity": "medium",
        "discovered_at": "2026-09-18T00:00:00Z",
    }


def _recon(findings, baseurls=(), domain="example.com"):
    return {
        "domain": domain,
        "vhost_sni": {
            "by_ip": {},
            "findings": list(findings),
            "discovered_baseurls": list(baseurls),
        },
    }


class TestNoDnsClaim(unittest.TestCase):
    def test_no_statement_ever_creates_a_resolves_to_edge(self):
        session = _Session(subdomains={"www.example.com"}, ips={"192.0.2.20"})
        _Client(session).update_graph_from_vhost_sni(
            _recon([_finding("www.example.com"), _finding("admin.example.com")]),
            "u", "p",
        )
        writes = [q for q, _ in session.calls
                  if "RESOLVES_TO" in q and "DELETE r" not in q]
        self.assertEqual(writes, [], "vhost/SNI evidence must not assert DNS resolution")

    def test_a_probed_pair_drops_the_stale_edge_earlier_releases_wrote(self):
        session = _Session(subdomains={"www.example.com"}, ips={"192.0.2.20"}, stale_edges=1)
        stats = _Client(session).update_graph_from_vhost_sni(
            _recon([_finding("www.example.com")]), "u", "p",
        )
        deletes = [(q, p) for q, p in session.calls if "DELETE r" in q]
        self.assertEqual(len(deletes), 1)
        query, params = deletes[0]
        self.assertIn("r.discovered_via = 'vhost_sni_enum'", query)
        self.assertIn("r.record_type IS NULL", query,
                      "an edge a DNS writer corroborated must survive")
        self.assertEqual(params["hostname"], "www.example.com")
        self.assertEqual(params["addr"], "192.0.2.20")
        self.assertEqual(stats["stale_dns_edges_removed"], 1)


class TestFindingsStayReachable(unittest.TestCase):
    def test_in_scope_candidate_gets_a_subdomain_flagged_unconfirmed(self):
        session = _Session(ips={"192.0.2.20"}, domains={"example.com"})
        stats = _Client(session).update_graph_from_vhost_sni(
            _recon([_finding("admin.example.com")]), "u", "p",
        )
        merges = [(q, p) for q, p in session.calls if "MERGE (s:Subdomain" in q]
        self.assertEqual(len(merges), 1, "an in-scope hidden vhost needs its node")
        query, params = merges[0]
        self.assertIn("ON CREATE SET s.source = 'vhost_sni_enum'", query)
        self.assertIn("s.has_dns_records = false", query,
                      "the name is unconfirmed until a resolver says otherwise")
        self.assertIn("MERGE (s)-[:HAS_VULNERABILITY]->(v)", query)
        self.assertEqual(params["hostname"], "admin.example.com")
        self.assertEqual(stats["subdomains_enriched"], 1)

    def test_in_scope_candidate_is_wired_to_its_parent_domain(self):
        session = _Session(ips={"192.0.2.20"}, domains={"example.com"})
        _Client(session).update_graph_from_vhost_sni(
            _recon([_finding("admin.example.com")]), "u", "p",
        )
        self.assertTrue(
            any("MERGE (d)-[:HAS_SUBDOMAIN]->(s)" in q for q, _ in session.calls),
            "a new in-scope subdomain must not float free of its domain",
        )

    def test_out_of_scope_candidate_anchors_to_the_ip_not_a_new_subdomain(self):
        session = _Session(ips={"192.0.2.20"})
        _Client(session).update_graph_from_vhost_sni(
            _recon([_finding("unrelated.co.uk")]), "u", "p",
        )
        self.assertFalse(
            any("MERGE (s:Subdomain" in q for q, _ in session.calls),
            "a co-hosted third party is not ours to add to the inventory",
        )
        self.assertTrue(
            any("MERGE (i)-[:HAS_VULNERABILITY]->(v)" in q for q, _ in session.calls),
            "the finding still has to hang off the IP that served it",
        )

    def test_lookalike_domain_is_not_treated_as_in_scope(self):
        session = _Session(ips={"192.0.2.20"})
        _Client(session).update_graph_from_vhost_sni(
            _recon([_finding("notexample.com")]), "u", "p",
        )
        self.assertFalse(
            any("MERGE (s:Subdomain" in q for q, _ in session.calls),
            "notexample.com is not a child of example.com",
        )

    def test_existing_subdomain_is_enriched_rather_than_duplicated(self):
        session = _Session(subdomains={"unrelated.co.uk"}, ips={"192.0.2.20"})
        stats = _Client(session).update_graph_from_vhost_sni(
            _recon([_finding("unrelated.co.uk")]), "u", "p",
        )
        self.assertFalse(any("MERGE (s:Subdomain" in q for q, _ in session.calls))
        enrich = [p for q, p in session.calls if "OPTIONAL MATCH (s:Subdomain" in q]
        self.assertEqual(enrich[0]["sprops"]["vhost_hidden"], True)
        self.assertEqual(stats["subdomains_enriched"], 1)


class TestDiscoveredBaseUrls(unittest.TestCase):
    def test_baseurl_for_an_out_of_scope_vhost_falls_back_to_its_service(self):
        session = _Session(ips={"192.0.2.20"}, services=1)
        stats = _Client(session).update_graph_from_vhost_sni(
            _recon([_finding("unrelated.co.uk")], baseurls=["https://unrelated.co.uk"]),
            "u", "p",
        )
        serves = [(q, p) for q, p in session.calls if "SERVES_URL" in q]
        self.assertEqual(len(serves), 1, "a BaseURL nobody owns is unreachable")
        self.assertEqual(serves[0][1]["addr"], "192.0.2.20")
        self.assertEqual(serves[0][1]["port"], 443)
        self.assertEqual(stats["baseurls_created"], 1)

    def test_baseurl_owned_by_a_subdomain_does_not_also_hit_the_service(self):
        session = _Session(subdomains={"hidden.example.com"}, ips={"192.0.2.20"})
        _Client(session).update_graph_from_vhost_sni(
            _recon([_finding("hidden.example.com")], baseurls=["https://hidden.example.com"]),
            "u", "p",
        )
        self.assertFalse(any("SERVES_URL" in q for q, _ in session.calls))

    def test_relationship_count_excludes_a_link_that_was_never_made(self):
        session = _Session(ips={"192.0.2.20"}, services=0)
        stats = _Client(session).update_graph_from_vhost_sni(
            _recon([], baseurls=["https://orphan.example.com"]), "u", "p",
        )
        self.assertEqual(stats["baseurls_created"], 1)
        self.assertEqual(stats["relationships_created"], 0,
                         "counting a link that does not exist hides the orphan")


class TestTenantScoping(unittest.TestCase):
    def test_every_statement_carries_the_tenant_pair(self):
        session = _Session(subdomains={"www.example.com"}, ips={"192.0.2.20"},
                           domains={"example.com"}, services=1)
        _Client(session).update_graph_from_vhost_sni(
            _recon(
                [_finding("www.example.com"),
                 _finding("admin.example.com"),
                 _finding("unrelated.co.uk"),
                 _finding("bypass.example.com", ftype="host_header_bypass")],
                baseurls=["https://admin.example.com"],
            ),
            "u", "p",
        )
        self.assertTrue(session.calls)
        for query, params in session.calls:
            self.assertEqual(params.get("uid"), "u", query)
            self.assertEqual(params.get("pid"), "p", query)
            for node in ("(s:Subdomain", "(i:IP", "(v:Vulnerability",
                         "(d:Domain", "(b:BaseURL", "(svc:Service"):
                if node in query:
                    self.assertIn("user_id: $uid", query, query)
                    self.assertIn("project_id: $pid", query, query)


if __name__ == "__main__":
    unittest.main()
