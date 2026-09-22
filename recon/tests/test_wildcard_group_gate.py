"""
Domain batch wildcard: the per-group gate, and the host merge behind it.

`run_domain_recon` is one 750-line phase, so the two decisions worth pinning are
tested as the functions the pipeline actually calls:

  group_discovery_enabled()  - may THIS target enumerate
  merge_group_hosts()        - what ends up scanned once discovery has answered

Both were extracted for exactly that reason. A test that re-stated either rule
inline would keep passing with the rule deleted.
"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.main import group_discovery_enabled, merge_group_hosts  # noqa: E402

LITERAL = {'rootDomain': 'lit.test', 'prefixes': ['api.']}
WILDCARD = {'rootDomain': 'wild.test', 'prefixes': ['*']}
ON = {'SUBDOMAIN_DISCOVERY_ENABLED': True}


def _info(**kw):
    base = {'include_root_domain': False, 'full_subdomains': [],
            'wildcard_mode': False, 'root_domain': 'wild.test'}
    base.update(kw)
    return base


class TestMixedBatchGate:
    """Row 2: in ONE run, the literal group must not enumerate and the wildcard
    group must. This is the whole contract of the feature: before it, the
    run-wide force-off made the answer the same for every group."""

    BATCH = [LITERAL, WILDCARD]

    def test_the_literal_group_does_not_enumerate(self):
        assert group_discovery_enabled(ON, self.BATCH, _info(wildcard_mode=False)) is False

    def test_the_wildcard_group_does_enumerate(self):
        assert group_discovery_enabled(ON, self.BATCH, _info(wildcard_mode=True)) is True

    def test_both_answers_come_from_the_same_run_wide_settings(self):
        # The settings dict is identical for both calls - only the group differs.
        literal = group_discovery_enabled(ON, self.BATCH, _info(wildcard_mode=False))
        wildcard = group_discovery_enabled(ON, self.BATCH, _info(wildcard_mode=True))
        assert (literal, wildcard) == (False, True)


class TestWildcardWithDiscoveryOff:
    """Row 3: a wildcard that cannot enumerate must never be reported as a
    successful empty group. run_domain_batch marks a group failed only on a
    non-zero return, so 'produced nothing' and 'succeeded' are indistinguishable
    unless this refuses."""

    def test_the_gate_says_no(self):
        off = {'SUBDOMAIN_DISCOVERY_ENABLED': False}
        assert group_discovery_enabled(off, [WILDCARD], _info(wildcard_mode=True)) is False

    def test_a_wildcard_with_no_listed_hosts_has_nothing_to_scan(self):
        # What run_domain_recon raises on: the merge yields an empty scan set,
        # which is the state that must not be allowed to look like success.
        merged = merge_group_hosts(None, _info(wildcard_mode=True), 'wild.test',
                                   ON, dns_enabled=False)
        assert merged["subdomains"] == []

    def test_a_wildcard_with_listed_hosts_falls_back_to_them(self):
        merged = merge_group_hosts(
            None, _info(wildcard_mode=True, full_subdomains=['api.wild.test']),
            'wild.test', ON, dns_enabled=False)
        assert merged["subdomains"] == ['api.wild.test']


class TestSeeding:
    """Row 4: a wildcard group may also name hosts. Enumeration is best-effort,
    so a named host must survive whether or not discovery found it."""

    def test_a_listed_host_survives_when_enumeration_misses_it(self):
        recon_result = {"subdomains": ["www.wild.test"],
                        "dns": {"domain": {}, "subdomains": {"www.wild.test": {}}}}
        merged = merge_group_hosts(
            recon_result, _info(wildcard_mode=True, full_subdomains=['api.wild.test']),
            'wild.test', ON, dns_enabled=False)
        assert "api.wild.test" in merged["subdomains"]
        assert "www.wild.test" in merged["subdomains"]

    def test_a_listed_host_is_not_duplicated_when_enumeration_finds_it(self):
        recon_result = {"subdomains": ["api.wild.test"], "dns": {}}
        merged = merge_group_hosts(
            recon_result, _info(wildcard_mode=True, full_subdomains=['api.wild.test']),
            'wild.test', ON, dns_enabled=False)
        assert merged["subdomains"].count("api.wild.test") == 1

    def test_single_domain_seeds_nothing(self):
        # full_subdomains is empty outside a wildcard group, so the seeding loop
        # must be inert on the ordinary path.
        recon_result = {"subdomains": ["www.wild.test"], "dns": {}}
        merged = merge_group_hosts(recon_result, _info(), 'wild.test', ON,
                                   dns_enabled=False)
        assert merged["subdomains"] == ["www.wild.test"]


class TestSeededHostsGetResolved:
    """Row 5: a seeded host carries no DNS of its own, and an unresolved host is
    invisible to the port scan - so seeding without resolving would be a host
    that appears in the file and is never actually scanned."""

    @staticmethod
    def _spy():
        calls = []

        def resolver(domain, subdomains, **kw):
            calls.append(list(subdomains))
            return {"domain": {"has_records": True},
                    "subdomains": {h: {"has_records": True} for h in subdomains}}
        return resolver, calls

    def test_resolves_the_seeded_host_even_when_discovery_resolved_others(self):
        # The bug this pins: keying the fallback on "discovery returned nothing"
        # skips this case entirely, because discovery DID return something.
        resolver, calls = self._spy()
        recon_result = {"subdomains": ["www.wild.test"],
                        "dns": {"domain": {}, "subdomains": {"www.wild.test": {"has_records": True}}}}
        merged = merge_group_hosts(
            recon_result, _info(wildcard_mode=True, full_subdomains=['api.wild.test']),
            'wild.test', ON, dns_enabled=True, resolver=resolver)
        assert calls == [["api.wild.test"]], "only the unresolved host is re-resolved"
        assert merged["dns"]["subdomains"]["api.wild.test"]["has_records"] is True
        # The host discovery already resolved is kept, not overwritten.
        assert "www.wild.test" in merged["dns"]["subdomains"]

    def test_resolves_everything_when_every_source_failed(self):
        # discover_subdomains() returns a TRUTHY dict with an empty list when all
        # five sources fail, so a falsy-check fallback would never fire here.
        resolver, calls = self._spy()
        recon_result = {"subdomains": [], "dns": {}}
        merged = merge_group_hosts(
            recon_result, _info(wildcard_mode=True,
                                full_subdomains=['api.wild.test', 'db.wild.test']),
            'wild.test', ON, dns_enabled=True, resolver=resolver)
        assert calls == [["api.wild.test", "db.wild.test"]]
        assert set(merged["dns"]["subdomains"]) == {"api.wild.test", "db.wild.test"}

    def test_does_not_resolve_when_dns_is_disabled(self):
        resolver, calls = self._spy()
        merge_group_hosts(
            {"subdomains": [], "dns": {}},
            _info(wildcard_mode=True, full_subdomains=['api.wild.test']),
            'wild.test', ON, dns_enabled=False, resolver=resolver)
        assert calls == []

    def test_does_not_resolve_when_nothing_is_missing(self):
        resolver, calls = self._spy()
        recon_result = {"subdomains": ["www.wild.test"],
                        "dns": {"domain": {}, "subdomains": {"www.wild.test": {}}}}
        merge_group_hosts(recon_result, _info(), 'wild.test', ON,
                          dns_enabled=True, resolver=resolver)
        assert calls == []


class TestIncludeRootIsAlwaysStamped:
    """Row 6: metadata['include_root_domain'] missing defaults to True in
    target_helpers, which scans the apex the operator left out."""

    @pytest.mark.parametrize("recon_result", [
        None,                                   # discovery skipped entirely
        {"subdomains": [], "dns": {}},          # every source failed (truthy)
        {"subdomains": ["www.wild.test"], "dns": {}},   # discovery worked
    ])
    def test_stamped_on_every_branch(self, recon_result):
        merged = merge_group_hosts(recon_result, _info(include_root_domain=False),
                                   'wild.test', ON, dns_enabled=False)
        assert merged["include_root"] is False

    def test_the_apex_is_added_only_when_asked_for(self):
        without = merge_group_hosts(None, _info(include_root_domain=False),
                                    'wild.test', ON, dns_enabled=False)
        assert 'wild.test' not in without["subdomains"]

        with_root = merge_group_hosts(None, _info(include_root_domain=True),
                                      'wild.test', ON, dns_enabled=False)
        assert with_root["subdomains"] == ['wild.test']
        assert with_root["include_root"] is True

    def test_the_apex_dns_is_only_populated_when_asked_for(self):
        resolver, calls = TestSeededHostsGetResolved._spy()
        merged = merge_group_hosts(
            {"subdomains": ["www.wild.test"], "dns": {"subdomains": {"www.wild.test": {}}}},
            _info(include_root_domain=False), 'wild.test', ON,
            dns_enabled=True, resolver=resolver)
        assert merged["dns"]["domain"] == {}


class TestDiscoveredHostsCannotPointInward:
    """A discovered name is the DOMAIN OWNER's DNS, not ours.

    `localhost.<domain> -> 127.0.0.1` is a real, common record - vulnweb.com
    publishes one, and an end-to-end run scanned it into the graph. Nothing
    downstream re-checks: port_scan and http_probe filter no addresses, so a
    host that reaches the scan set is a host that gets probed. Loopback means
    the scanner probes itself; link-local means cloud metadata.

    The guard is deliberately NARROWER than is_non_routable_ip: RFC-1918 is kept,
    because RedAmon scans internal estates on purpose and dropping private
    addresses would silently break those engagements.
    """

    @staticmethod
    def _dns(mapping):
        return {"domain": {}, "subdomains": {
            h: {"ips": {"ipv4": v, "ipv6": []}, "has_records": True}
            for h, v in mapping.items()}}

    def _merge(self, mapping, listed=()):
        hosts = list(mapping)
        return merge_group_hosts(
            {"subdomains": hosts, "dns": self._dns(mapping)},
            _info(wildcard_mode=True, full_subdomains=list(listed)),
            "wild.test", ON, dns_enabled=False)

    def test_loopback_is_dropped(self):
        m = self._merge({"www.wild.test": ["93.184.216.34"],
                         "localhost.wild.test": ["127.0.0.1"]})
        assert "localhost.wild.test" not in m["subdomains"]
        assert "www.wild.test" in m["subdomains"]
        # and its DNS goes with it, so nothing downstream can resurrect it
        assert "localhost.wild.test" not in m["dns"]["subdomains"]

    @pytest.mark.parametrize("ip", [
        "127.0.0.1", "::1",
        "169.254.169.254",          # cloud metadata
        "::ffff:169.254.169.254",   # the same, IPv4-mapped
        "0.0.0.0", "224.0.0.1",
    ])
    def test_every_never_scannable_address_is_dropped(self, ip):
        m = self._merge({"evil.wild.test": [ip]})
        assert m["subdomains"] == []

    def test_a_private_address_is_KEPT(self):
        # Internal engagements are a supported mode; dropping RFC-1918 here
        # would break them silently. This is the line between the two filters.
        m = self._merge({"intranet.wild.test": ["10.0.0.5"]})
        assert m["subdomains"] == ["intranet.wild.test"]

    def test_a_host_the_operator_LISTED_is_never_dropped(self):
        # They typed it. Scanning it is their decision, not discovery's.
        m = self._merge({"localhost.wild.test": ["127.0.0.1"]},
                        listed=["localhost.wild.test"])
        assert m["subdomains"] == ["localhost.wild.test"]

    def test_the_apex_is_never_dropped(self):
        m = merge_group_hosts(
            {"subdomains": [], "dns": self._dns({"wild.test": ["127.0.0.1"]})},
            _info(wildcard_mode=True, include_root_domain=True),
            "wild.test", ON, dns_enabled=False)
        assert "wild.test" in m["subdomains"]

    def test_a_host_with_one_bad_address_among_good_ones_is_dropped(self):
        # DNS rebinding returns both; keeping it because one address was fine
        # is the whole attack.
        m = self._merge({"rebind.wild.test": ["93.184.216.34", "127.0.0.1"]})
        assert m["subdomains"] == []
