"""The RoE parse endpoint must resolve an LLM without a project loaded.

The bug this pins, found by driving the real feature end to end:

`_setup_llm_for_endpoint` read `USER_LLM_PROVIDERS` out of the orchestrator's
loaded PROJECT settings. But a RoE document is uploaded while a project is being
CREATED - that is the only place the UI offers the upload - so there is no
project, and on a freshly started agent no project has ever been loaded. The
provider list was empty, no API key resolved, and `setup_llm` raised. Every
parse answered:

    503 {"error": "LLM not available for model <whatever>"}

for every model, with two working providers configured in the database.

It looked like a model-routing problem and was not. It was an endpoint reading
its credentials out of a scope it does not have.

The fix: the caller's user id travels with the request and the agent fetches
THAT user's providers. These tests hold the two halves - the request carries the
id, and an empty project scope no longer decides the answer.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
for path in (str(REPO_ROOT), str(REPO_ROOT / "agentic")):
    if path not in sys.path:
        sys.path.insert(0, path)

WEBAPP_ROUTE = REPO_ROOT / "webapp" / "src" / "app" / "api" / "roe" / "parse" / "route.ts"
AGENT_API = REPO_ROOT / "agentic" / "api.py"


def test_the_request_model_carries_a_user_id():
    """Without it the agent has nothing to resolve providers against."""
    source = AGENT_API.read_text(encoding="utf-8")
    block = source[source.index("class RoeParseRequest"):]
    block = block[:block.index("\n\n\n")] if "\n\n\n" in block else block
    assert "user_id" in block


def test_the_webapp_route_sends_the_caller_id():
    """It is the only party that knows who is asking."""
    source = WEBAPP_ROUTE.read_text(encoding="utf-8")
    assert "getEffectiveUser" in source
    assert "user_id: userId" in source or "...(userId && { user_id: userId })" in source


def test_the_endpoint_passes_the_id_into_the_llm_setup():
    """A id that arrives and is then dropped is the same bug with extra steps."""
    source = AGENT_API.read_text(encoding="utf-8")
    assert "_setup_llm_for_endpoint(requested_model, body.user_id)" in source


def test_an_empty_project_scope_no_longer_decides_the_answer():
    """The regression itself, at the seam where it lived.

    Project settings hold no providers - the state a fresh agent is always in -
    and a user id is supplied. The setup must reach for that user's providers
    rather than concluding there are none.
    """
    import api

    fetched: list[str] = []

    def fake_fetch(user_id: str):
        fetched.append(user_id)
        return [{"providerType": "deepseek", "apiKey": "sk-test", "name": "DeepSeek"}]

    with patch.object(api, "_fetch_user_llm_providers", fake_fetch), \
         patch("project_settings.get_settings", return_value={"USER_LLM_PROVIDERS": []}), \
         patch("orchestrator_helpers.llm_setup.setup_llm") as setup:
        api._setup_llm_for_endpoint("deepseek/deepseek-chat", "user-123")

    assert fetched == ["user-123"], "the caller's providers were never fetched"
    assert setup.call_args.kwargs.get("deepseek_api_key") == "sk-test"


def test_a_loaded_project_scope_still_wins_and_costs_no_fetch():
    """When a project IS loaded its providers are already correct.

    Fetching again would add a webapp round trip to every agent-side call for no
    new information.
    """
    import api

    fetched: list[str] = []

    with patch.object(api, "_fetch_user_llm_providers", lambda u: fetched.append(u) or []), \
         patch(
             "project_settings.get_settings",
             return_value={"USER_LLM_PROVIDERS": [
                 {"providerType": "kimi", "apiKey": "sk-loaded", "name": "Kimi"}
             ]},
         ), \
         patch("orchestrator_helpers.llm_setup.setup_llm") as setup:
        api._setup_llm_for_endpoint("kimi/kimi-k2", "user-123")

    assert fetched == [], "re-fetched providers the loaded project already had"
    assert setup.call_args.kwargs.get("kimi_api_key") == "sk-loaded"


def test_no_user_id_means_no_fetch_rather_than_a_crash():
    """An older client that does not send the id must still behave as before."""
    import api

    with patch.object(api, "_fetch_user_llm_providers") as fetch, \
         patch("project_settings.get_settings", return_value={"USER_LLM_PROVIDERS": []}), \
         patch("orchestrator_helpers.llm_setup.setup_llm"):
        api._setup_llm_for_endpoint("deepseek/deepseek-chat", None)

    fetch.assert_not_called()


def test_an_unreachable_webapp_is_an_empty_list_not_an_exception():
    """The caller turns an empty list into a 503 naming the model.

    A raise here would surface as a 500 with a stack trace instead, which tells
    an operator nothing about the missing provider.
    """
    import api

    with patch("requests.get", side_effect=OSError("webapp down")):
        assert api._fetch_user_llm_providers("user-123") == []
