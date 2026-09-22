"""Third-party hosts named by a target's JavaScript reach the ExternalDomain aggregate.

JS recon no longer writes an Endpoint for a host outside the scan scope, so the
external-domain aggregate is the only place those hosts are recorded. The shapes
below are the ones a real IP-mode run against testing/guinea_pigs/js_scope_target
produced.
"""
import os
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)


def _js_external(*domains):
    return [{"domain": d, "source": "js_recon", "urls": [f"https://{d}/x"], "times_seen": 1}
            for d in domains]


class TestJsReconExternalDomains(unittest.TestCase):
    def _aggregate(self, combined_result):
        from recon.main import _aggregate_external_domains
        return {e["domain"]: e for e in _aggregate_external_domains(combined_result)}

    def test_ip_mode_keeps_third_parties_and_drops_the_target_ip(self):
        out = self._aggregate({
            "subdomains": ["192-88-97-10"],
            "metadata": {"subdomain_filter": ["192.88.97.10", "192-88-97-10"],
                         "expanded_ips": ["192.88.97.10"]},
            "js_recon": {"external_domains": _js_external(
                "192.88.97.10", "api.payments-vendor.test", "192.88.97.20")},
        })
        self.assertEqual(sorted(out), ["192.88.97.20", "api.payments-vendor.test"])
        self.assertEqual(out["api.payments-vendor.test"]["sources"], ["js_recon"])
        # A URL a bundle names is not a redirect target.
        self.assertEqual(out["api.payments-vendor.test"]["redirect_to_urls"], [])

    def test_domain_mode_drops_scanned_subdomains(self):
        out = self._aggregate({
            "subdomains": ["app.example.com"],
            "metadata": {"subdomain_filter": []},
            "js_recon": {"external_domains": _js_external("APP.example.com", "cdn.vendor.test")},
        })
        self.assertEqual(sorted(out), ["cdn.vendor.test"])

    def test_merges_with_other_sources(self):
        out = self._aggregate({
            "resource_enum": {"external_domains": [{"domain": "cdn.vendor.test",
                                                    "source": "katana"}]},
            "js_recon": {"external_domains": _js_external("cdn.vendor.test")},
        })
        self.assertEqual(out["cdn.vendor.test"]["sources"], ["katana", "js_recon"])
        self.assertEqual(out["cdn.vendor.test"]["times_seen"], 2)

    def test_no_js_recon_output_adds_nothing(self):
        self.assertEqual(self._aggregate({"js_recon": {}}), {})
        self.assertEqual(self._aggregate({}), {})

    def test_malformed_entries_are_skipped(self):
        out = self._aggregate({"js_recon": {"external_domains": [
            None, "bare-string.test", {"domain": None}, {"urls": []},
            {"domain": "ok.vendor.test"},
        ]}})
        self.assertEqual(sorted(out), ["ok.vendor.test"])


if __name__ == "__main__":
    unittest.main()
