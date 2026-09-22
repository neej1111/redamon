"""
Parse the `settings[...] = project.get(...)` block out of a project_settings.py.

525 of these mappings are byte-identical in form, which is what makes generating
them feasible. The handful that are not carry semantics a naive generator would
erase, so this parser records the SHAPE of each mapping rather than assuming the
canonical one:

  canonical   settings['K'] = project.get('k', DEFAULT_SETTINGS['K'])
  falsy       settings['K'] = project.get('k') or DEFAULT_SETTINGS['K']
  coerced     settings['K'] = int(project.get('k', DEFAULT_SETTINGS['K']))
  stripped    settings['K'] = project.get('k', DEFAULT_SETTINGS['K']).strip()

`fallback: falsy` is the one that bites: a stored `0` or `[]` is replaced by the
default rather than honoured, so emitting the canonical form for it changes
behaviour with nothing failing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# settings['RUNTIME_KEY'] = <expr>
_ASSIGN_RE = re.compile(r"^\s*settings\[(['\"])(?P<key>[A-Z0-9_]+)\1\]\s*=\s*(?P<expr>.+?)\s*$")
_GET_RE = re.compile(r"project\.get\(\s*(['\"])(?P<col>[A-Za-z0-9_]+)\1")


@dataclass
class Mapping:
    runtime_key: str
    column: str
    fallback: str  # 'missing' | 'falsy'
    coerce: str | None  # None | 'int' | 'strip' | 'strip_list'
    canonical: bool
    expr: str
    line: int


def parse_mappings(path: Path) -> dict[str, Mapping]:
    """runtime_key -> Mapping, for every `settings[K] = project.get(col, ...)` line."""
    out: dict[str, Mapping] = {}
    text = path.read_text(encoding="utf-8")
    for lineno, line in enumerate(text.splitlines(), start=1):
        m = _ASSIGN_RE.match(line)
        if not m:
            continue
        expr = m.group("expr")
        g = _GET_RE.search(expr)
        if not g:
            continue
        key = m.group("key")
        col = g.group("col")

        fallback = "falsy" if re.search(r"\)\s*or\s+", expr) else "missing"
        coerce = None
        if expr.startswith("int("):
            coerce = "int"
        elif expr.rstrip().endswith(".strip()"):
            coerce = "strip"

        canonical = (
            expr == f"project.get('{col}', DEFAULT_SETTINGS['{key}'])"
            and fallback == "missing"
            and coerce is None
        )
        out[key] = Mapping(
            runtime_key=key,
            column=col,
            fallback=fallback,
            coerce=coerce,
            canonical=canonical,
            expr=expr,
            line=lineno,
        )
    return out


def parse_default_settings(path: Path, name: str = "DEFAULT_SETTINGS") -> dict[str, object]:
    """
    A settings-defaults dict, evaluated in an empty namespace.

    Parameterised because there are two: the recon pipeline's `DEFAULT_SETTINGS`
    and the agent's `DEFAULT_AGENT_SETTINGS`. They read the same project row
    through two modules, and a few keys exist only on one side.
    """
    text = path.read_text(encoding="utf-8")
    start = text.index(f"{name}: dict[str, Any] = {{")
    open_brace = text.index("{", start)
    depth = 0
    i = open_brace
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    literal = text[open_brace : i + 1]
    ns: dict[str, object] = {}
    exec(f"VALUE = {literal}", ns)  # noqa: S102 - our own source file, not input
    return ns["VALUE"]  # type: ignore[return-value]


if __name__ == "__main__":  # pragma: no cover - a manual inspection aid
    import json

    recon = REPO_ROOT / "recon" / "project_settings.py"
    maps = parse_mappings(recon)
    odd = {k: v.expr for k, v in maps.items() if not v.canonical}
    print(json.dumps({"mappings": len(maps), "non_canonical": odd}, indent=1))
