"""
The recon settings registry, on the Python side.

`recon_settings/registry.json` is a build artifact of `registry.yaml`; this
module reads it with nothing but the standard library, so a scan container needs
no new dependency to know what a parameter means or what its ceiling is.

FAIL CLOSED. A missing or unparseable registry raises, and the caller must not
continue on shipped defaults. A scan that silently runs on fallback defaults is
a scan running without the engagement ceiling, which is the one failure this
whole layer exists to prevent.

The query helpers mirror `webapp/src/lib/reconSettings/registry.ts` name for
name, so a derived list cannot mean one thing in TypeScript and another here.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable

# The registry ships beside the code in every image that needs it. Search order:
# an explicit override, the repo layout (host, tests), then the container layout
# where `recon_settings/` is mounted next to `recon/`.
_CANDIDATES = (
    Path(__file__).resolve().parent / "registry.json",
    Path("/app/recon_settings/registry.json"),
    Path("/app/recon/recon_settings/registry.json"),
)


class RegistryUnavailable(RuntimeError):
    """The registry could not be read. Never recoverable: the scan must stop."""


def registry_path() -> Path:
    override = os.environ.get("RECON_SETTINGS_REGISTRY")
    if override:
        path = Path(override)
        if not path.is_file():
            raise RegistryUnavailable(
                f"RECON_SETTINGS_REGISTRY points at {override}, which is not a readable file."
            )
        return path
    for candidate in _CANDIDATES:
        if candidate.is_file():
            return candidate
    searched = ", ".join(str(c) for c in _CANDIDATES)
    raise RegistryUnavailable(
        "The recon settings registry was not found. A scan cannot start without it, "
        "because the engagement ceiling and every parameter bound are defined there. "
        f"Searched: {searched}. Set RECON_SETTINGS_REGISTRY to override."
    )


@lru_cache(maxsize=1)
def load_registry() -> dict[str, Any]:
    path = registry_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RegistryUnavailable(f"The recon settings registry at {path} is unreadable: {exc}") from exc
    for key in ("fields", "tools", "runtime_only"):
        if not isinstance(data.get(key), dict):
            raise RegistryUnavailable(f"The registry at {path} has no '{key}' section.")
    return data


def reload_registry() -> dict[str, Any]:
    """Drop the cache and re-read. For tests and for a live registry swap."""
    load_registry.cache_clear()
    return load_registry()


def fields() -> dict[str, dict[str, Any]]:
    return load_registry()["fields"]


def tools() -> dict[str, dict[str, Any]]:
    return load_registry()["tools"]


def runtime_only() -> dict[str, dict[str, Any]]:
    return load_registry()["runtime_only"]


def fields_where(pred: Callable[[dict[str, Any], str], bool]) -> dict[str, dict[str, Any]]:
    """The query helper every derived list goes through."""
    return {k: v for k, v in sorted(fields().items()) if pred(v, k)}


def field(column: str) -> dict[str, Any] | None:
    return fields().get(column)


def by_runtime_key() -> dict[str, dict[str, Any]]:
    """runtime_key -> the field entry. Keys are unique; the gate asserts it."""
    out: dict[str, dict[str, Any]] = {}
    for column, entry in fields().items():
        key = entry.get("runtime_key")
        if key:
            out[key] = {"column": column, **entry}
    return out


# --- the derived lists --------------------------------------------------------------

def roe_capped_runtime_keys() -> list[str]:
    """
    Every runtime key the engagement rate ceiling applies to.

    This replaced a hardcoded list of fifteen that three live rate fields were
    missing from. Membership is still not the same as being capped: the capper
    below has to handle a `0` that means unlimited, which is why `zero_means`
    exists and why the test asserts the RESOLVED value.
    """
    keys = {
        entry["runtime_key"]
        for entry in fields().values()
        if entry.get("roe_capped") and entry.get("runtime_key")
    }
    keys |= {k for k, v in runtime_only().items() if v.get("roe_capped")}
    return sorted(keys)


def unlimited_zero_runtime_keys() -> set[str]:
    """Runtime keys where a stored `0` means UNLIMITED, not "slowest"."""
    keys = {
        entry["runtime_key"]
        for entry in fields().values()
        if entry.get("zero_means") == "unlimited" and entry.get("runtime_key")
    }
    keys |= {k for k, v in runtime_only().items() if v.get("zero_means") == "unlimited"}
    return keys


def _governed(model: str) -> dict[str, dict[str, Any]]:
    """runtime_key -> governor block, for one model, across columns and runtime keys."""
    out: dict[str, dict[str, Any]] = {}
    for entry in fields().values():
        gov = entry.get("governor")
        key = entry.get("runtime_key")
        if gov and key and gov.get("model") == model:
            out[key] = gov
    for key, entry in runtime_only().items():
        gov = entry.get("governor")
        if gov and gov.get("model") == model:
            out[key] = gov
    return out


def governor_ratio_keys() -> dict[str, int]:
    """
    Concurrency knobs the memory governor scales by ratio -> their floor.

    Not derived from `unit`: half the model's thread-shaped fields are not
    governed, and inferring "every threads field is scaled" would start capping
    values the governor has never touched. The registry records the table and
    the runtime reads it.
    """
    return {key: int(gov["floor"]) for key, gov in _governed("ratio").items()}


def governor_budget_keys() -> dict[str, tuple[str, int]]:
    """In-memory accumulators the governor budgets -> (bytes-per-unit family, floor)."""
    return {
        key: (str(gov["family"]), int(gov["floor"]))
        for key, gov in _governed("budget").items()
    }


def stealth_profile() -> dict[str, dict[str, Any]]:
    """
    runtime_key -> the stealth operation, across columns and runtime-only keys.

    Two operations, and the difference is load-bearing. `set` FORCES a value, so
    stealth wins whatever the operator chose. `ceiling` lowers a value to at most
    N and leaves an already-quieter one alone, which is what the six
    `min(settings.get(k), 100)` lines did: an operator who asked for 50 results
    keeps 50 rather than being raised to 100.
    """
    out: dict[str, dict[str, Any]] = {}
    for entry in fields().values():
        key, spec = entry.get("runtime_key"), entry.get("stealth")
        if key and spec:
            out[key] = spec
    for key, entry in runtime_only().items():
        if entry.get("stealth"):
            out[key] = entry["stealth"]
    return out


def project_file_runtime_keys() -> list[str]:
    """Runtime keys holding an absolute filesystem path a scan container opens."""
    return sorted(
        entry["runtime_key"]
        for entry in fields().values()
        if entry.get("validator") == "project_file" and entry.get("runtime_key")
    )


def project_file_name_runtime_keys() -> list[str]:
    """
    Runtime keys holding a BASENAME the scan joins onto a mounted directory.

    Separate from `project_file` because the dangerous input is different: here
    the value never carries a root at all, and `../../etc/passwd` joined onto
    /custom-templates escapes it.
    """
    return sorted(
        entry["runtime_key"]
        for entry in fields().values()
        if entry.get("validator") == "project_file_name" and entry.get("runtime_key")
    )


def bounds_for(runtime_key: str) -> tuple[float, float] | None:
    entry = by_runtime_key().get(runtime_key)
    if not entry:
        return None
    b = entry.get("bounds")
    return (b["min"], b["max"]) if b else None


def meaning_for(column: str) -> str:
    entry = field(column)
    return entry["meaning"] if entry else ""


def iter_capped(settings: Iterable[str]) -> list[str]:
    """The capped keys actually present in a settings dict, in registry order."""
    present = set(settings)
    return [k for k in roe_capped_runtime_keys() if k in present]
