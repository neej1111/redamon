"""
Domain batch: the `*` sentinel that makes ONE group enumerate.

A batch has always scanned exactly the hostnames it was given, and three places
encode that as a refusal rather than a default: the settings force-off, the
parser dropping a group with no prefixes, and parse_target treating a bare root
as "not filtered". A wildcard is that refusal turned into a feature for one
group at a time, so the tests below pin the seam from both sides: a wildcard
group must enumerate, and every OTHER group in the same run must not.

The second half pins the metacharacter contract. `*` lives in a prefix list and
nowhere else; it must never become a hostname, because from there it reaches a
tool argument, a filename and a Cypher MERGE.
"""

import ast
import re
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.main import group_discovery_enabled  # noqa: E402
from recon.project_settings import _parse_domain_batch_groups  # noqa: E402

HOSTNAME_SAFE = re.compile(r'^[a-z0-9.-]+$')


def _parse_target():
    """Load parse_target without importing recon.main.

    recon/main.py calls get_settings() at import time, which reaches for the
    webapp API. The function under test is pure, so it is lifted out of the AST
    instead - the alternative is a module-level network call inside the gate.
    """
    src = (PROJECT_ROOT / "recon" / "main.py").read_text()
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == "parse_target")
    ns = {"re": re,
          "_PREFIX_CHARSET": re.compile(r'^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$')}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "<parse_target>", "exec"), ns)
    return ns["parse_target"]


parse_target = _parse_target()


class TestParseTargetSentinels:
    """The two sentinels, and the modes they select."""

    @pytest.mark.parametrize("prefixes,filtered,wildcard,include_root", [
        # A bare root is NOT filtered mode: "." says "also scan the apex", it
        # does not say "skip discovery". Pre-existing contract, pinned here
        # because the wildcard work sits right next to it.
        (["."], False, False, True),
        (["*"], False, True, False),
        (["*", "."], False, True, True),
        # A wildcard WINS over explicit siblings: the group enumerates, and the
        # siblings are seeded into the result rather than replacing discovery.
        (["api.", "*"], False, True, False),
        (["*", "api."], False, True, False),
        (["api."], True, False, False),
        ([], False, False, False),
    ])
    def test_mode_matrix(self, prefixes, filtered, wildcard, include_root):
        info = parse_target("example.com", prefixes)
        assert info["filtered_mode"] is filtered
        assert info["wildcard_mode"] is wildcard
        assert info["include_root_domain"] is include_root

    def test_the_sentinel_never_becomes_a_hostname(self):
        info = parse_target("example.com", ["*", ".", "api."])
        assert "*.example.com" not in info["full_subdomains"]
        assert all(HOSTNAME_SAFE.match(h) for h in info["full_subdomains"])

    def test_a_wildcard_group_seeds_its_explicit_siblings(self):
        # Enumeration is not guaranteed to surface a host the operator listed,
        # so the listed ones are carried forward to be merged with whatever
        # discovery finds.
        info = parse_target("example.com", ["api.", "*"])
        assert info["full_subdomains"] == ["api.example.com"]


class TestTheTrailingDotTrap:
    """`*.` is not the sentinel, and must not become a host either.

    toStoredPrefixes() in TargetSection appends a trailing dot, so an operator
    typing `*` into the single-domain Subdomain Prefixes box produces `*.`.
    Matching the sentinel after rstrip('.') would turn that box - whose entire
    job is to NARROW scope - into a silent full-enumeration switch.
    """

    def test_a_trailing_dot_star_does_not_enable_enumeration(self):
        info = parse_target("example.com", ["*."])
        assert info["wildcard_mode"] is False

    @pytest.mark.parametrize("prefix", ["*.", "*", "../etc/", "a;whoami",
                                        "a b", "evil'})--", "x\\y"])
    def test_an_unusable_prefix_never_reaches_full_subdomains(self, prefix):
        # SUBDOMAIN_LIST gets no charset check in fetch_project_settings (it is
        # only whitespace-stripped), so a row written through the API or the
        # database can put anything here.
        info = parse_target("example.com", [prefix])
        assert all(HOSTNAME_SAFE.match(h) for h in info["full_subdomains"])
        assert f"{prefix.rstrip('.')}.example.com" not in info["full_subdomains"]

    def test_a_dropped_prefix_does_not_select_filtered_mode(self):
        # Filtered mode with nothing to scan is the silent-empty-run failure the
        # auto-promote guard exists to prevent, so the count must come from what
        # survived rather than from what was supplied.
        info = parse_target("example.com", ["../etc/"])
        assert info["filtered_mode"] is False
        assert info["full_subdomains"] == []

    def test_a_good_prefix_survives_beside_a_dropped_one(self):
        info = parse_target("example.com", ["api.", "x;"])
        assert info["full_subdomains"] == ["api.example.com"]
        assert info["filtered_mode"] is True


class TestSettingsBoundary:
    """_parse_domain_batch_groups re-validates what the webapp derived."""

    def test_keeps_the_wildcard_sentinel(self):
        groups = _parse_domain_batch_groups(
            [{'rootDomain': 'example.com', 'prefixes': ['*']}])
        assert groups == [{'rootDomain': 'example.com', 'prefixes': ['*']}]

    def test_keeps_a_wildcard_beside_real_prefixes(self):
        groups = _parse_domain_batch_groups(
            [{'rootDomain': 'example.com', 'prefixes': ['api.', '*', '.']}])
        assert groups[0]['prefixes'] == ['api.', '*', '.']

    def test_still_drops_everything_that_is_not_a_sentinel_or_a_label(self):
        groups = _parse_domain_batch_groups([
            {'rootDomain': 'example.com', 'prefixes': ['*', '../etc/', 'a..b', 'ok.']},
        ])
        assert groups[0]['prefixes'] == ['*', 'ok.']

    def test_a_wildcard_on_a_public_suffix_is_demoted_not_honoured(self):
        # rootOf() is last-two-labels, so `acme.co.uk` reduces to `co.uk`. For a
        # literal group that is a harmless documented quirk; a wildcard would
        # mean "enumerate every subdomain of co.uk".
        groups = _parse_domain_batch_groups([
            {'rootDomain': 'co.uk', 'prefixes': ['*', 'acme.']},
        ])
        assert groups[0]['prefixes'] == ['acme.']

    def test_a_wildcard_only_group_on_a_public_suffix_is_dropped_whole(self):
        assert _parse_domain_batch_groups(
            [{'rootDomain': 'com.au', 'prefixes': ['*']}]) == []

    def test_a_wildcard_on_an_ordinary_domain_is_untouched(self):
        groups = _parse_domain_batch_groups(
            [{'rootDomain': 'example.co', 'prefixes': ['*']}])
        assert groups[0]['prefixes'] == ['*']


class TestPerGroupGate:
    """Whether a target may enumerate is decided per group, not per run.

    Calls the real gate. Re-stating the expression here would produce a test
    that still passes with the gate deleted, which is the failure mode this
    class exists to avoid.
    """

    LITERAL = {'rootDomain': 'lit.test', 'prefixes': ['api.']}
    WILDCARD = {'rootDomain': 'wild.test', 'prefixes': ['*']}

    def test_single_domain_follows_the_toggle(self):
        assert group_discovery_enabled({'SUBDOMAIN_DISCOVERY_ENABLED': True}, [],
                                       {'wildcard_mode': False}) is True
        assert group_discovery_enabled({'SUBDOMAIN_DISCOVERY_ENABLED': False}, [],
                                       {'wildcard_mode': False}) is False

    def test_a_literal_batch_group_never_enumerates(self):
        # Even with the toggle on, which is what a mixed batch leaves it as.
        assert group_discovery_enabled(
            {'SUBDOMAIN_DISCOVERY_ENABLED': True},
            [self.LITERAL, self.WILDCARD],
            {'wildcard_mode': False}) is False

    def test_a_wildcard_batch_group_enumerates(self):
        assert group_discovery_enabled(
            {'SUBDOMAIN_DISCOVERY_ENABLED': True},
            [self.LITERAL, self.WILDCARD],
            {'wildcard_mode': True}) is True

    def test_the_operator_toggle_still_wins(self):
        assert group_discovery_enabled(
            {'SUBDOMAIN_DISCOVERY_ENABLED': False},
            [self.WILDCARD],
            {'wildcard_mode': True}) is False

    def test_the_default_is_enumeration_when_the_key_is_absent(self):
        # DEFAULT_SETTINGS ships it True; an absent key must not silently
        # disable discovery for a single-domain project.
        assert group_discovery_enabled({}, [], {}) is True
