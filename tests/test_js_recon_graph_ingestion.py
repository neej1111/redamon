import hashlib
import os
import re
import sys
import unittest
from unittest.mock import MagicMock


_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.recon.js_recon_mixin import (
    JsReconMixin, js_endpoint_scope, split_absolute_endpoint,
)


class FakeSession:
    def __init__(self, endpoint_created=True, endpoint_linked=True):
        self.calls = []
        self.endpoint_created = endpoint_created
        self.endpoint_linked = endpoint_linked

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def run(self, query, **kwargs):
        self.calls.append((query, kwargs))
        if "RETURN created AS created" in query:
            return FakeResult({"created": self.endpoint_created})
        if "RETURN count(r) AS linked" in query:
            return FakeResult({"linked": 1 if self.endpoint_linked else 0})
        return FakeResult({"enriched": 0})


class FakeResult:
    def __init__(self, record):
        self.record = record

    def single(self):
        return self.record


class FakeDriver:
    def __init__(self, endpoint_created=True, endpoint_linked=True):
        self.session_obj = FakeSession(
            endpoint_created=endpoint_created,
            endpoint_linked=endpoint_linked,
        )

    def session(self):
        return self.session_obj


class GraphClient(JsReconMixin):
    def __init__(self, endpoint_created=True, endpoint_linked=True):
        self.driver = FakeDriver(
            endpoint_created=endpoint_created,
            endpoint_linked=endpoint_linked,
        )


class TestJsReconGraphIngestion(unittest.TestCase):
    def test_only_confirmed_dead_endpoints_are_dropped_with_validation_metadata_and_id(self):
        client = GraphClient()
        recon_data = {
            "domain": "example.com",
            "js_recon": {
                "scan_metadata": {"scan_timestamp": "2026-05-28T00:00:00Z"},
                "endpoints": [
                    {
                        "path": "/api/live",
                        "method": "POST",
                        "source_js": "https://example.com/app.js",
                        "base_url": "https://example.com",
                        "full_url": "https://example.com/api/live",
                        "validation_status": "hittable",
                        "status_code": 200,
                        "resolved_url": "https://example.com/api/live",
                    },
                    {
                        "path": "/api/dead",
                        "method": "GET",
                        "source_js": "https://example.com/app.js",
                        "base_url": "https://example.com",
                        "validation_status": "not_hittable",
                    },
                    {
                        "path": "/api/unknown",
                        "method": "GET",
                        "source_js": "https://example.com/app.js",
                        "base_url": "https://example.com",
                    },
                ],
            },
        }

        stats = client.update_graph_from_js_recon(recon_data, "u1", "p1")

        endpoint_calls = [
            kwargs for query, kwargs in client.driver.session_obj.calls
            if "MERGE (e:Endpoint" in query
        ]
        ingested_paths = {kwargs["path"] for kwargs in endpoint_calls}
        # 'hittable' and the un-probed 'unknown' endpoint are ingested; only the
        # probe-confirmed 'not_hittable' endpoint is dropped.
        self.assertEqual(stats["endpoints_created"], 2)
        self.assertEqual(ingested_paths, {"/api/live", "/api/unknown"})
        self.assertNotIn("/api/dead", ingested_paths)

        live_call = next(k for k in endpoint_calls if k["path"] == "/api/live")
        expected_hash = hashlib.sha256(
            "https://example.com:POST:/api/live".encode()
        ).hexdigest()[:16]
        self.assertEqual(live_call["id"], f"endpoint-u1-p1-js-{expected_hash}")
        self.assertEqual(live_call["validation_status"], "hittable")
        self.assertEqual(live_call["status_code"], 200)
        self.assertEqual(live_call["resolved_url"], "https://example.com/api/live")
        link_calls = [
            (query, kwargs) for query, kwargs in client.driver.session_obj.calls
            if "MERGE (file)-[r:HAS_ENDPOINT]->(n)" in query
        ]
        self.assertEqual(len(link_calls), 2)
        self.assertIn("MATCH (n:Endpoint {path: $path, method: $method, baseurl: $baseurl", link_calls[0][0])
        self.assertNotIn("MATCH (n:Endpoint {id: $nid})", link_calls[0][0])
        self.assertEqual(stats["errors"], [])

    def test_existing_endpoint_and_unmatched_file_link_do_not_increment_counts(self):
        client = GraphClient(endpoint_created=False, endpoint_linked=False)
        recon_data = {
            "domain": "example.com",
            "js_recon": {
                "scan_metadata": {"scan_timestamp": "2026-05-28T00:00:00Z"},
                "endpoints": [
                    {
                        "path": "/api/live",
                        "method": "POST",
                        "source_js": "https://example.com/app.js",
                        "base_url": "https://example.com",
                        "full_url": "https://example.com/api/live",
                        "validation_status": "hittable",
                        "status_code": 200,
                        "resolved_url": "https://example.com/api/live",
                    },
                ],
            },
        }

        stats = client.update_graph_from_js_recon(recon_data, "u1", "p1")

        self.assertEqual(stats["endpoints_created"], 0)
        self.assertEqual(stats["relationships_created"], 1)
        link_calls = [
            (query, kwargs) for query, kwargs in client.driver.session_obj.calls
            if "MERGE (file)-[r:HAS_ENDPOINT]->(n)" in query
        ]
        self.assertEqual(len(link_calls), 1)
        self.assertEqual(stats["errors"], [])

    def test_unvalidated_endpoints_are_ingested_when_probing_is_off(self):
        # With endpoint probing disabled (the default), every endpoint is tagged
        # 'unvalidated'. These must still reach the graph — disabling probing keeps
        # the prior "ingest every extracted endpoint" behavior.
        client = GraphClient()
        recon_data = {
            "domain": "example.com",
            "js_recon": {
                "scan_metadata": {"scan_timestamp": "2026-05-28T00:00:00Z"},
                "endpoints": [
                    {
                        "path": "/api/a",
                        "method": "GET",
                        "source_js": "https://example.com/app.js",
                        "base_url": "https://example.com",
                        "validation_status": "unvalidated",
                        "validation_error": "validation_disabled",
                    },
                    {
                        "path": "/api/b",
                        "method": "GET",
                        "source_js": "https://example.com/app.js",
                        "base_url": "https://example.com",
                        "validation_status": "unvalidated",
                        "validation_error": "validation_disabled",
                    },
                ],
            },
        }

        stats = client.update_graph_from_js_recon(recon_data, "u1", "p1")

        endpoint_calls = [
            kwargs for query, kwargs in client.driver.session_obj.calls
            if "MERGE (e:Endpoint" in query
        ]
        self.assertEqual(stats["endpoints_created"], 2)
        self.assertEqual({k["path"] for k in endpoint_calls}, {"/api/a", "/api/b"})
        self.assertEqual(stats["errors"], [])


class TestJsReconFindingPackageFields(unittest.TestCase):
    """package_name / package_version on JsReconFinding nodes.

    The JS Dep Signals table has had Package and Version columns since it was
    written, reading `name` and `version` - properties nothing ever set, so both
    columns rendered empty on every row. They are written under a `package_`
    prefix because `name` is what the graph viewer displays as the node label
    (format.ts falls back to `title` only when `name` is absent), so using it
    would relabel every framework node from "React 18.2.0" to "React".
    """

    @staticmethod
    def _finding_props(client, finding_type):
        for query, kwargs in client.driver.session_obj.calls:
            if "MERGE (jf:JsReconFinding" not in query:
                continue
            props = kwargs.get("props") or {}
            if props.get("finding_type") == finding_type:
                return props
        return None

    def test_dependency_confusion_carries_the_package_name(self):
        client = GraphClient()
        client.update_graph_from_js_recon({
            "domain": "example.com",
            "js_recon": {
                "scan_metadata": {"scan_timestamp": "2026-08-07T00:00:00Z"},
                "dependencies": [{
                    "id": "dep1",
                    "finding_type": "dependency_confusion",
                    "package_name": "@acme/internal-utils",
                    "severity": "critical",
                    "title": "Dependency confusion: @acme/internal-utils not on public npm",
                    "source_url": "https://example.com/app.js",
                }],
            },
        }, "u1", "p1")
        props = self._finding_props(client, "dependency_confusion")
        self.assertIsNotNone(props)
        self.assertEqual(props["package_name"], "@acme/internal-utils")
        # `name` stays unset so the graph node label keeps using `title`.
        self.assertNotIn("name", props)

    def test_framework_carries_name_and_version_separately_from_the_label(self):
        client = GraphClient()
        client.update_graph_from_js_recon({
            "domain": "example.com",
            "js_recon": {
                "scan_metadata": {"scan_timestamp": "2026-08-07T00:00:00Z"},
                "frameworks": [{
                    "id": "fw1", "name": "React", "version": "18.2.0",
                    "source_url": "https://example.com/app.js",
                }],
            },
        }, "u1", "p1")
        props = self._finding_props(client, "framework")
        self.assertIsNotNone(props)
        self.assertEqual(props["package_name"], "React")
        self.assertEqual(props["package_version"], "18.2.0")
        self.assertEqual(props["title"], "React 18.2.0")
        self.assertNotIn("name", props)


def _ep(path, base_url="", source_js="https://app.example.com/static/main.js", **extra):
    return {"path": path, "method": extra.pop("method", "GET"), "source_js": source_js,
            "base_url": base_url, "validation_status": "unvalidated", **extra}


def _domain_run(endpoints, subdomains=("app.example.com",), dns_subdomains=None, **metadata):
    return {
        "domain": "example.com",
        "subdomains": list(subdomains),
        "dns": {"subdomains": dns_subdomains or {}},
        "metadata": metadata,
        "js_recon": {"scan_metadata": {}, "endpoints": endpoints},
    }


# The owner write, with the tenant key spelled out inside the MERGE pattern: a
# key passed only as a parameter would still merge across projects.
_OWNER_MERGE = re.compile(
    r"MERGE \(bu:BaseURL \{url: \$baseurl, user_id: \$uid, project_id: \$pid\}\)")
_OWNER_MATCH = re.compile(
    r"MATCH \(e:Endpoint \{path: \$path, method: \$method, baseurl: \$baseurl, "
    r"user_id: \$uid, project_id: \$pid\}\)")


class TestJsReconEndpointScopeAndOwnership(unittest.TestCase):
    """JS-extracted endpoints: third-party hosts never become Endpoints, and an
    in-scope Endpoint hangs off its BaseURL like every other endpoint does."""

    def _ingest(self, recon_data, **client_kwargs):
        client = GraphClient(**client_kwargs)
        stats = client.update_graph_from_js_recon(recon_data, "u1", "p1")
        calls = client.driver.session_obj.calls
        endpoints = [kw for q, kw in calls if "MERGE (e:Endpoint" in q]
        owners = [(q, kw) for q, kw in calls if "MERGE (bu:BaseURL" in q]
        return stats, endpoints, owners

    def test_third_party_absolute_url_is_not_written(self):
        stats, endpoints, owners = self._ingest(_domain_run([
            _ep("/v1/charges", base_url="https://api.payments-vendor.test"),
        ]))
        self.assertEqual(endpoints, [])
        self.assertEqual(owners, [])
        self.assertEqual(stats["endpoints_out_of_scope"], 1)
        self.assertEqual(stats["endpoints_created"], 0)
        self.assertEqual(stats["errors"], [])

    def test_in_scope_endpoint_is_owned_by_its_base_url(self):
        stats, endpoints, owners = self._ingest(_domain_run([
            _ep("/api/users", base_url="https://app.example.com"),
        ]))
        self.assertEqual([(e["baseurl"], e["path"]) for e in endpoints],
                         [("https://app.example.com", "/api/users")])
        self.assertEqual(len(owners), 1)
        query, params = owners[0]
        self.assertRegex(query, _OWNER_MERGE)
        self.assertRegex(query, _OWNER_MATCH)
        self.assertIn("MERGE (bu)-[r:HAS_ENDPOINT]->(e)", query)
        # First writer only: httpx owns the BaseURL's own source tag.
        self.assertIn("ON CREATE SET bu.source = 'js_recon'", query)
        self.assertNotRegex(query, r"(?<!ON CREATE )SET bu\.source")
        self.assertEqual(
            {k: params[k] for k in ("baseurl", "path", "method", "uid", "pid")},
            {"baseurl": "https://app.example.com", "path": "/api/users",
             "method": "GET", "uid": "u1", "pid": "p1"})
        self.assertEqual(stats["endpoints_out_of_scope"], 0)

    def test_relative_path_takes_the_js_file_host(self):
        _, endpoints, owners = self._ingest(_domain_run([_ep("/api/orders")]))
        self.assertEqual(endpoints[0]["baseurl"], "https://app.example.com")
        self.assertEqual(owners[0][1]["baseurl"], "https://app.example.com")

    def test_relative_path_in_js_served_from_a_third_party_cdn_is_dropped(self):
        stats, endpoints, _ = self._ingest(_domain_run([
            _ep("/api/orders", source_js="https://cdn.vendor.test/bundle.js"),
        ]))
        self.assertEqual(endpoints, [])
        self.assertEqual(stats["endpoints_out_of_scope"], 1)

    def test_uploaded_relative_path_keeps_the_upload_pseudo_base_and_no_owner(self):
        stats, endpoints, owners = self._ingest(_domain_run([
            _ep("/api/upload-only", source_js="upload://bundle.js"),
        ]))
        self.assertEqual([(e["baseurl"], e["path"]) for e in endpoints],
                         [("upload", "/api/upload-only")])
        self.assertEqual(owners, [])
        self.assertEqual(stats["endpoints_out_of_scope"], 0)

    def test_absolute_url_in_uploaded_js_is_scope_checked(self):
        _, endpoints, _ = self._ingest(_domain_run([
            _ep("https://api.payments-vendor.test/v1", source_js="upload://bundle.js",
                type="config"),
            _ep("https://app.example.com/v2/me", source_js="upload://bundle.js",
                type="config"),
        ]))
        self.assertEqual([(e["baseurl"], e["path"]) for e in endpoints],
                         [("https://app.example.com", "/v2/me")])

    def test_whole_url_carried_in_path_is_split_and_scoped(self):
        # config / graphql / custom_keyword matches put the full URL in `path`
        # with no base_url; they used to be filed under the JS file's host.
        stats, endpoints, _ = self._ingest(_domain_run([
            _ep("https://api.payments-vendor.test/v1/config", type="config"),
            _ep("https://app.example.com/graphql?op=q", type="graphql", method="POST"),
        ]))
        self.assertEqual([(e["baseurl"], e["path"], e["method"]) for e in endpoints],
                         [("https://app.example.com", "/graphql", "POST")])
        self.assertEqual(stats["endpoints_out_of_scope"], 1)

    def test_websocket_is_owned_by_the_http_origin_of_its_handshake(self):
        _, endpoints, owners = self._ingest(_domain_run([
            _ep("wss://app.example.com/socket", type="websocket", method="WS"),
            _ep("wss://push.vendor.test/socket", type="websocket", method="WS"),
        ]))
        self.assertEqual([(e["baseurl"], e["path"], e["method"]) for e in endpoints],
                         [("https://app.example.com", "/socket", "WS")])
        self.assertEqual(owners[0][1]["baseurl"], "https://app.example.com")

    def test_explicit_port_is_in_scope(self):
        _, endpoints, _ = self._ingest(_domain_run([
            _ep("/admin", base_url="https://app.example.com:8443"),
        ]))
        self.assertEqual(endpoints[0]["baseurl"], "https://app.example.com:8443")

    def test_subdomain_js_recon_vetted_is_in_scope_but_an_untagged_dns_entry_is_not(self):
        # merge_discovered_hostnames tags what it admits; the domain run copies
        # dns.subdomains wholesale, so an untagged name may be RoE-excluded.
        stats, endpoints, _ = self._ingest(_domain_run(
            [
                _ep("/v1/items", base_url="https://api.example.com"),
                _ep("/v1/items", base_url="https://excluded.example.com"),
            ],
            dns_subdomains={
                "api.example.com": {"has_records": True, "source": "js_recon"},
                "excluded.example.com": {"has_records": True},
            },
        ))
        self.assertEqual([e["baseurl"] for e in endpoints], ["https://api.example.com"])
        self.assertEqual(stats["endpoints_out_of_scope"], 1)

    def test_filtered_run_keeps_exactly_the_users_list(self):
        _, endpoints, _ = self._ingest(_domain_run(
            [_ep("/v1/items", base_url="https://api.example.com")],
            dns_subdomains={"api.example.com": {"has_records": True, "source": "js_recon"}},
            filtered_mode=True, subdomain_filter=["app.example.com"],
        ))
        self.assertEqual(endpoints, [])

    def test_ip_mode_scope_is_the_target_ips_not_the_placeholder_names(self):
        recon_data = {
            "domain": "ip-targets.p1",
            "subdomains": ["192-88-97-10"],
            "metadata": {"ip_mode": True, "filtered_mode": True,
                         "subdomain_filter": ["192.88.97.10"],
                         "expanded_ips": ["192.88.97.10"]},
            "js_recon": {"scan_metadata": {}, "endpoints": [
                _ep("/api/users", source_js="http://192.88.97.10/static/app.js"),
                _ep("/api/x", base_url="http://192.88.97.20"),
            ]},
        }
        stats, endpoints, _ = self._ingest(recon_data)
        self.assertEqual([e["baseurl"] for e in endpoints], ["http://192.88.97.10"])
        self.assertEqual(stats["endpoints_out_of_scope"], 1)

    def test_no_scope_at_all_filters_nothing(self):
        recon_data = {"js_recon": {"scan_metadata": {}, "endpoints": [
            _ep("/v1", base_url="https://anything.test"),
        ]}}
        stats, endpoints, _ = self._ingest(recon_data)
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(stats["endpoints_out_of_scope"], 0)

    def test_owner_link_counts_only_when_linked(self):
        stats, _, owners = self._ingest(
            _domain_run([_ep("/api/users", base_url="https://app.example.com")]),
            endpoint_linked=False)
        self.assertEqual(len(owners), 1)
        # Only the file node's own HAS_JS_FILE edge counts: neither the
        # file->endpoint nor the owner edge reported a link.
        self.assertEqual(stats["relationships_created"], 1)

    def test_no_query_deletes_anything(self):
        client = GraphClient()
        client.update_graph_from_js_recon(_domain_run([
            _ep("/api/users", base_url="https://app.example.com"),
            _ep("/v1", base_url="https://api.payments-vendor.test"),
        ]), "u1", "p1")
        for query, _ in client.driver.session_obj.calls:
            self.assertNotRegex(query, r"\bDELETE\b|\bREMOVE\s+\w+:")


class TestSplitAbsoluteEndpoint(unittest.TestCase):
    def test_cases(self):
        js = "https://app.example.com/main.js"
        cases = {
            "/api/v1": ("", "/api/v1"),
            "https://h.test/a/b?x=1#f": ("https://h.test", "/a/b"),
            "https://h.test": ("https://h.test", "/"),
            "http://h.test:8080/p": ("http://h.test:8080", "/p"),
            "wss://h.test/s": ("https://h.test", "/s"),
            "ws://h.test/s": ("http://h.test", "/s"),
            "//h.test/p": ("https://h.test", "/p"),
            "ftp://h.test/p": ("", "ftp://h.test/p"),
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(split_absolute_endpoint(path, js), expected)

    def test_protocol_relative_follows_the_js_scheme(self):
        self.assertEqual(split_absolute_endpoint("//h.test/p", "http://app.example.com/a.js"),
                         ("http://h.test", "/p"))
        self.assertEqual(split_absolute_endpoint("//h.test/p", "upload://a.js"),
                         ("https://h.test", "/p"))


class TestJsEndpointScope(unittest.TestCase):
    def test_empty_stays_empty_so_nothing_is_filtered(self):
        self.assertEqual(js_endpoint_scope({"dns": {"subdomains": {
            "api.example.com": {"source": "js_recon"}}}}), set())

    def test_list_shaped_dns_subdomains_add_nothing(self):
        # partial recon passes graph subdomains as a list of dicts; its scope
        # comes from the top-level list instead.
        scope = js_endpoint_scope({"domain": "example.com", "subdomains": ["www.example.com"],
                                   "dns": {"subdomains": [{"subdomain": "x.example.com"}]}})
        self.assertEqual(scope, {"www.example.com"})

    def test_all_vetted_sources_are_admitted(self):
        scope = js_endpoint_scope({"subdomains": ["app.example.com"], "dns": {"subdomains": {
            "a.example.com": {"source": "js_recon"},
            "b.example.com": {"source": "tlsx"},
            "c.example.com": {"source": "certificate_san"},
            "d.example.com": {"source": "crt.sh"},
        }}})
        self.assertEqual(scope, {"app.example.com", "a.example.com", "b.example.com",
                                 "c.example.com"})


if __name__ == "__main__":
    unittest.main()
