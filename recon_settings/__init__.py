"""The recon settings registry, as an importable package.

`registry.yaml` is the authored source, `registry.json` its build artifact, and
this package is how every service reads it. Three services import it on three
different schedules - the agent has it COPY-baked, recon mounts it, the
orchestrator mounts it read-only - so a rule that lives in one of them and is
re-implemented in the others is the drift this package exists to remove.

Nothing here needs a third-party dependency: reading the built registry uses the
standard library only, and only `build.py` wants PyYAML.
"""
from .loader import (  # noqa: F401
    RegistryUnavailable,
    bounds_for,
    by_runtime_key,
    field,
    fields,
    fields_where,
    governor_budget_keys,
    governor_ratio_keys,
    iter_capped,
    load_registry,
    meaning_for,
    project_file_name_runtime_keys,
    project_file_runtime_keys,
    registry_path,
    reload_registry,
    roe_capped_runtime_keys,
    runtime_only,
    stealth_profile,
    tools,
    unlimited_zero_runtime_keys,
)
from .engagement import (  # noqa: F401
    ENGAGEMENT_LIMIT_GROUP,
    derive_roe_enabled,
    engagement_limit_columns,
    engagement_record_columns,
    strip_engagement_limits,
)
