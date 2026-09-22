"""
Parse the Prisma `Project` model into scalar columns, types and defaults.

Prisma owns existence, type and `@default()`; the recon settings registry never
restates them. This is the join the registry build and the extraction script
both use on the Python side. The TypeScript side reads the same facts from the
DMMF instead of re-parsing, so neither language is the other's source.

Deliberately a small regex parser and not a Prisma dependency: it runs on the
host, in the recon image and in the agent image, none of which has node.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field as dc_field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "webapp" / "prisma" / "schema.prisma"

# A scalar column line: `name  Type  @attr...`. Relations are excluded by
# checking the type against the scalar set below, which is why `user User` and
# `conversations Conversation[]` fall out without a model index.
_FIELD_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+"
    r"(?P<type>[A-Za-z]+)(?P<list>\[\])?(?P<optional>\?)?"
    r"(?P<attrs>\s+@.*)?$"
)

_SCALARS = {"String", "Boolean", "Int", "Float", "DateTime", "Json", "BigInt", "Decimal", "Bytes"}


@dataclass
class Column:
    name: str
    type: str
    is_list: bool
    optional: bool
    default_raw: str | None
    doc: str = ""

    @property
    def kind(self) -> str:
        """The coarse shape the registry validates against."""
        if self.is_list:
            return "string-list" if self.type == "String" else "number-list"
        if self.type == "Boolean":
            return "boolean"
        if self.type in ("Int", "BigInt"):
            return "int"
        if self.type in ("Float", "Decimal"):
            return "float"
        if self.type == "Json":
            return "json"
        if self.type == "DateTime":
            return "datetime"
        return "string"

    @property
    def default_value(self):
        """
        The `@default()` argument as a Python value, or None when there is none.

        A quoted default is a Prisma STRING LITERAL, so its backslash escapes
        have to be undone: a Json column's default is a quoted JSON document and
        keeping the escapes would produce a value that only looks right.
        """
        raw = self.default_raw
        if raw is None:
            return None
        if raw in ("true", "false"):
            return raw == "true"
        if raw == "[]":
            return []
        if raw.startswith('"') and raw.endswith('"'):
            return json.loads(raw)
        if raw.startswith("[") and raw.endswith("]"):
            inner = raw[1:-1].strip()
            if not inner:
                return []
            parts = [p.strip() for p in inner.split(",")]
            # A list default is typed by the column, not by the literal: Int[]
            # carries numbers and String[] carries strings.
            if self.type in ("Int", "BigInt"):
                return [int(p) for p in parts]
            if self.type in ("Float", "Decimal"):
                return [float(p) for p in parts]
            return [json.loads(p) if p.startswith('"') else p for p in parts]
        try:
            return int(raw)
        except ValueError:
            pass
        try:
            return float(raw)
        except ValueError:
            pass
        # cuid(), now(), autoincrement(), dbgenerated(...): a function, not a value.
        return None


@dataclass
class Model:
    name: str
    columns: dict[str, Column] = dc_field(default_factory=dict)


def _split_default(attrs: str) -> str | None:
    """Extract the `@default(...)` argument, balancing nested parens and quotes."""
    idx = attrs.find("@default(")
    if idx < 0:
        return None
    i = idx + len("@default(")
    depth = 1
    out = []
    in_str = False
    while i < len(attrs) and depth:
        ch = attrs[i]
        if in_str:
            out.append(ch)
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
            out.append(ch)
        elif ch == "(":
            depth += 1
            out.append(ch)
        elif ch == ")":
            depth -= 1
            if depth:
                out.append(ch)
        else:
            out.append(ch)
        i += 1
    return "".join(out).strip()


def parse_model(model_name: str, schema_path: Path | None = None) -> Model:
    text = (schema_path or SCHEMA_PATH).read_text(encoding="utf-8")
    start = re.search(rf"^model {re.escape(model_name)} \{{", text, re.MULTILINE)
    if not start:
        raise KeyError(f"model {model_name} not found in {schema_path or SCHEMA_PATH}")
    body_start = start.end()
    depth = 1
    i = body_start
    while i < len(text) and depth:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    body = text[body_start : i - 1]

    model = Model(name=model_name)
    pending_doc: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("///"):
            pending_doc.append(stripped[3:].strip())
            continue
        if not stripped or stripped.startswith("//") or stripped.startswith("@@"):
            pending_doc = []
            continue
        m = _FIELD_RE.match(line)
        if not m or m.group("type") not in _SCALARS:
            pending_doc = []
            continue
        attrs = m.group("attrs") or ""
        model.columns[m.group("name")] = Column(
            name=m.group("name"),
            type=m.group("type"),
            is_list=bool(m.group("list")),
            optional=bool(m.group("optional")),
            default_raw=_split_default(attrs),
            doc=" ".join(pending_doc).strip(),
        )
        pending_doc = []
    return model


def project_columns(schema_path: Path | None = None) -> dict[str, Column]:
    return parse_model("Project", schema_path).columns


if __name__ == "__main__":  # pragma: no cover - a manual inspection aid
    import json

    cols = project_columns()
    print(json.dumps({"count": len(cols), "columns": sorted(cols)}, indent=1))
