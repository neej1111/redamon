"""The registry's forbidden-tool vocabulary must match the agent's real tools.

`roeForbiddenTools` is enforced by an EXACT string match in
`execute_plan_node._check_roe_blocked`:

    forbidden = set(get_setting('ROE_FORBIDDEN_TOOLS', []))
    ...
    if tool_name in forbidden:

so a name that is merely close does not partially block anything - it blocks
nothing, while the ban is stored, rendered in the UI as a rule, and repeated to
the agent as prompt advice. That is how a live project came to hold
`execute_sqlmap`, which is not a tool, next to a UI placeholder that suggested
it.

The column is now a closed vocabulary in `recon_settings/registry.yaml`, which
both teaches the RoE parse prompt the exact tokens and refuses anything else at
the write. The cost of closing it is a second list of tool names that can drift
from the first. This is the guard for that: adding a tool to `TOOL_PHASE_MAP`
without adding it to the registry would make it the one tool an engagement cannot
forbid, and nothing else would say so.

`roeForbiddenCategories` has the same shape against `CATEGORY_TOOL_MAP`.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
for path in (str(REPO_ROOT), str(REPO_ROOT / "agentic")):
    if path not in sys.path:
        sys.path.insert(0, path)

REGISTRY = json.loads((REPO_ROOT / "recon_settings" / "registry.json").read_text(encoding="utf-8"))
SETTINGS_SRC = (REPO_ROOT / "agentic" / "project_settings.py").read_text(encoding="utf-8")
GATE_SRC = (
    REPO_ROOT / "agentic" / "orchestrator_helpers" / "nodes" / "execute_plan_node.py"
).read_text(encoding="utf-8")


def _braced_block(source: str, needle: str) -> str:
    """The `{...}` literal that follows `needle`, balanced."""
    start = source.index(needle)
    open_at = source.index("{", start)
    depth = 0
    for i in range(open_at, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[open_at:i]
    raise AssertionError(f"unbalanced block after {needle!r}")


def agent_tool_names() -> set[str]:
    block = _braced_block(SETTINGS_SRC, "'TOOL_PHASE_MAP': {")
    return set(re.findall(r"'([a-z0-9_]+)':\s*\[", block))


def registry_values(key: str) -> set[str]:
    spec = REGISTRY["fields"].get(key)
    assert spec is not None, f"{key} is not in the registry"
    values = spec.get("values")
    assert values, f"{key} has no closed vocabulary; a free-text ban is never enforced"
    return set(values)


def test_the_vocabulary_is_closed_at_all():
    # The regression itself. Free text here is not a looser rule, it is no rule.
    assert registry_values("roeForbiddenTools")
    assert registry_values("roeForbiddenCategories")


def test_every_forbiddable_tool_is_a_real_agent_tool():
    """A token the dispatcher will never see cannot forbid anything."""
    unknown = registry_values("roeForbiddenTools") - agent_tool_names()
    assert not unknown, (
        f"registry offers tool names the agent does not dispatch: {sorted(unknown)}"
    )


def test_every_agent_tool_can_be_forbidden():
    """The other direction: a tool nobody can ban is a hole in the engagement."""
    missing = agent_tool_names() - registry_values("roeForbiddenTools")
    assert not missing, (
        "these tools are dispatchable but cannot be named in roeForbiddenTools; "
        f"add them to registry.yaml and rebuild: {sorted(missing)}"
    )


def test_execute_sqlmap_is_not_offered():
    """The specific value a live project held, from the form's own placeholder."""
    assert "execute_sqlmap" not in registry_values("roeForbiddenTools")


def test_every_forbiddable_category_is_one_the_gate_expands():
    """A category the map does not know expands to nothing and refuses nothing."""
    block = _braced_block(GATE_SRC, "CATEGORY_TOOL_MAP = {")
    known = set(re.findall(r"'([a-z_]+)':\s*\[", block))
    assert known, "CATEGORY_TOOL_MAP could not be read"

    offered = registry_values("roeForbiddenCategories")
    # `physical` is offered by the form and reaches the agent's prompt as advice,
    # but has no entry in the map. It is tracked rather than asserted away, so
    # this test fails the day a NEW unenforced token is added.
    unenforced = offered - known
    assert unenforced <= {"physical"}, (
        f"categories that expand to no tools at all: {sorted(unenforced - {'physical'})}"
    )


def test_the_gate_still_matches_exactly():
    """If this ever became a fuzzy match, the closed vocabulary could relax.

    Until then the exactness is the reason the vocabulary has to be closed, so
    the two facts are pinned together.
    """
    assert "if tool_name in forbidden:" in GATE_SRC
