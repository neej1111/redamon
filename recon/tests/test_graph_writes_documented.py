"""The catalog must describe every edge the CODE can write.

The live-graph oracle in test_schema_catalog.py can only see what this
deployment happened to scan. A relationship belonging to a feature nobody ran
here is invisible to it, which is a large blind spot: most deployments run a
fraction of the eleven scanners.

This checks the other direction, against the code, and is fully hermetic - no
database, so unlike the live oracle it actually runs in CI.

It found five undocumented relationship types on its first run (HAS_IP,
DISCOVERED_FROM and the three ChainFinding FINDING_AFFECTS_* edges), plus a real
bug that had nothing to do with documentation: see the phantom test below.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CATALOG_PY = PROJECT_ROOT / "graph_db" / "schema_catalog.py"

#: Files that CONTAIN the documentation, or that carry illustrative Cypher for a
#: different purpose. Scanning them would let the schema prove itself correct by
#: quoting itself.
SKIP_FILES = {
    "schema_catalog.py",   # the catalog itself
    "base.py",             # the prompt: examples, not writes
    "tool_registry.py",    # tool descriptions
    "rce_prompts.py",      # attack-prompt examples against a generic graph
}

SEARCH_ROOTS = ("graph_db", "recon", "scanners", "recon_orchestrator", "agentic")

#: Placeholders that are not relationship types: `-[:REL]` in a worked example,
#: `-[:STEP_*]` in a docstring describing a family of edges.
NOT_A_TYPE = {"REL", "STEP_", "RUNS"}


def _load(path: Path, name: str):
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


catalog = _load(CATALOG_PY, "schema_catalog")


def _source_files() -> list[Path]:
    out = []
    for root in SEARCH_ROOTS:
        d = PROJECT_ROOT / root
        if not d.exists():
            continue
        out += [
            f
            for f in d.rglob("*.py")
            if "test" not in str(f) and f.name not in SKIP_FILES
        ]
    return out


def _scan() -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """(written, read) -> {relationship type: [file:line]}.

    A line carrying MERGE or CREATE writes the edge; anything else reads it.
    The variable binding is optional, so `-[r:WAF_BYPASS_VIA]->` counts as a
    write: missing that cost me two false phantoms on the first pass.
    """
    written: dict[str, list[str]] = {}
    read: dict[str, list[str]] = {}
    for f in _source_files():
        rel = f.relative_to(PROJECT_ROOT)
        for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").split("\n"), 1):
            for t in re.findall(r"-\[\w*:(\w+)", line):
                if t in NOT_A_TYPE:
                    continue
                bucket = written if re.search(r"\b(MERGE|CREATE)\b", line) else read
                bucket.setdefault(t, []).append(f"{rel}:{i}")
    return written, read


def test_every_relationship_the_code_writes_is_documented():
    """An edge the schema never mentions is an edge the agent cannot traverse.

    Nothing fails today when a scanner adds one: the graph simply grows a
    connection the agent is blind to, and the answer comes back incomplete
    rather than wrong, which is much harder to notice.
    """
    written, _ = _scan()
    missing = {t: v for t, v in written.items() if t not in catalog.RELATIONSHIP_TYPES}
    assert not missing, (
        f"{len(missing)} relationship type(s) are written by the code but absent "
        "from the schema catalog, so the agent cannot traverse them:\n"
        + "\n".join(f"  {t}  ({v[0]})" for t, v in sorted(missing.items()))
    )


def test_no_query_reads_a_relationship_nothing_ever_writes():
    """A phantom edge: a query that can never match.

    This is not a documentation problem, it is a silent logic bug. It found
    `user_input_mixin.py` reading `(p)-[:HAS_SERVICE]->(:Service)` where every
    writer creates `RUNS_SERVICE`, so the Httpx partial-recon modal reported
    `existing_baseurls_count` as 0 no matter how many existed. No error, no
    empty-result warning - just a number that was always zero.
    """
    written, read = _scan()
    phantom = {t: v for t, v in read.items() if t not in written}
    assert not phantom, (
        "relationship type(s) are READ by a query but written NOWHERE, so those "
        "patterns can never match:\n"
        + "\n".join(f"  {t}  ({', '.join(v[:2])})" for t, v in sorted(phantom.items()))
    )


def _properties_written() -> dict[str, set[str]]:
    """{label: property names} from explicit Cypher across the codebase.

    Only sees properties written literally - `SET n.foo = ...` or a `{foo: $x}`
    map. The 22 labels using `SET n += $props` build their dict in Python, so
    their names appear in no file and only the live graph knows them. That is
    why BOTH oracles exist: this one covers features nobody ran here, the live
    one covers the dynamic writers.
    """
    out: dict[str, set[str]] = {}
    for f in _source_files():
        src = f.read_text(encoding="utf-8", errors="replace")
        blocks = re.findall(r'"""(.*?)"""', src, re.S) + re.findall(r'"([^"\n]{30,})"', src)
        for q in blocks:
            if not re.search(r"\b(MERGE|CREATE|SET)\b", q):
                continue
            binds: dict[str, str] = {}
            for var, lab in re.findall(r"\((\w+):(\w+)", q):
                binds.setdefault(var, lab)
            for _var, lab, body in re.findall(r"\((\w+):(\w+)\s*\{([^}]*)\}", q):
                for prop in re.findall(r"(\w+)\s*:", body):
                    out.setdefault(lab, set()).add(prop)
            for var, prop in re.findall(r"\b(\w+)\.(\w+)\s*=", q):
                if var in binds:
                    out.setdefault(binds[var], set()).add(prop)
    return out


def test_every_property_the_code_writes_is_documented():
    """Same blind spot as relationships had.

    The live-graph oracle only sees properties this deployment happened to
    produce. EPSS scoring on CVE, cpe_vendor on Technology, fixed_version on
    Vulnerability - 30 of these existed with no schema entry because no scan
    here had ever written one.
    """
    render = _load(PROJECT_ROOT / "graph_db" / "schema_render.py", "schema_render")
    doc = render.render_schema() + (
        PROJECT_ROOT / "agentic" / "prompts" / "base.py"
    ).read_text(encoding="utf-8")
    ignore = {"user_id", "project_id"}
    missing = {}
    for lab, props in _properties_written().items():
        if lab not in catalog.DOCUMENTED:
            continue  # label coverage is the other suite's job
        gone = sorted(
            p for p in props
            if p not in ignore and not p.startswith("triage") and p not in doc
        )
        if gone:
            missing[lab] = gone
    assert not missing, (
        f"{sum(len(v) for v in missing.values())} propert(ies) are written by the "
        "code but absent from the schema, so the agent cannot name them:\n"
        + "\n".join(f"  {lab}: {', '.join(ps)}" for lab, ps in sorted(missing.items()))
    )


def test_the_scan_finds_a_plausible_number_of_writes():
    """Guards against the scan silently matching nothing and passing vacuously."""
    written, _ = _scan()
    assert len(written) > 50, (
        f"only {len(written)} relationship types found in the codebase; the "
        "scanner or the SKIP list is probably wrong, making both tests above vacuous"
    )


if __name__ == "__main__":
    passed, failures = 0, []
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS  {name}")
                passed += 1
            except AssertionError as exc:
                print(f"  FAIL  {name}: {exc}")
                failures.append(name)
            except Exception as exc:  # noqa: BLE001
                print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
                failures.append(name)
    print()
    print(f"{passed} passed, {len(failures)} failed")
    sys.exit(1 if failures else 0)


# ---------------------------------------------------------------------------
# Properties applied via `SET n += $props`
# ---------------------------------------------------------------------------
# The scan above reads property names out of the Cypher text, so it cannot see a
# property whose name only ever exists as a dict key in Python. `wildcard_mode`
# is one of those: removing its line from schema_sections.md leaves every test
# above green. It is load-bearing - it is the only thing distinguishing "this
# Domain was enumerated" from "this Domain was scanned as listed" - so it gets a
# behavioural test of its own.

class _FakeSession:
    """Captures every Cypher call instead of running it."""

    def __init__(self, sink):
        self.sink = sink

    def run(self, query, **params):
        self.sink.append((query, params))
        return []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeDriver:
    def __init__(self, sink):
        self.sink = sink

    def session(self):
        return _FakeSession(self.sink)


def _domain_props_for(metadata_extra: dict) -> dict:
    """Run the real mixin against a fake driver and return the Domain props."""
    from graph_db.mixins.recon.domain_mixin import DomainMixin

    class _Client(DomainMixin):
        def __init__(self, sink):
            self.driver = _FakeDriver(sink)

    sink: list = []
    recon_data = {
        "metadata": {"root_domain": "example.com", "target": "example.com",
                     **metadata_extra},
        "whois": {}, "subdomains": [], "dns": {},
    }
    _Client(sink).update_graph_from_domain_discovery(recon_data, "u1", "p1")
    for query, params in sink:
        if "MERGE (d:Domain" in query:
            return params["props"]
    raise AssertionError("the Domain MERGE never ran")


def test_wildcard_mode_is_written_onto_the_domain_node():
    # A mixed batch writes both values in one run, so the flag has to travel from
    # the recon metadata onto the node rather than being inferred later.
    assert _domain_props_for({"wildcard_mode": True})["wildcard_mode"] is True
    assert _domain_props_for({"wildcard_mode": False})["wildcard_mode"] is False


def test_wildcard_mode_defaults_to_false_for_older_recon_files():
    # A recon file written before this feature has no such key. It must read as
    # "not enumerated" rather than raising or writing None.
    assert _domain_props_for({})["wildcard_mode"] is False


def test_wildcard_mode_is_declared_in_the_schema():
    # Declared in ONE place; schema_catalog.py is generated from it.
    sections = (PROJECT_ROOT / "graph_db" / "schema_sections.md").read_text()
    domain_block = sections.split("**Domain**", 1)[1].split("**Subdomain**", 1)[0]
    assert "wildcard_mode" in domain_block
