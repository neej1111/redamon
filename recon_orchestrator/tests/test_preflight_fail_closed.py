"""P0-1: the guardrail / RoE pre-flight must fail CLOSED.

Before this fix the pre-flight caught every exception, logged "proceeding" and
ran the scan with neither the hard guardrail nor the RoE time window applied.
That was tolerable while every start came from a human clicking a button in the
UI. It is not tolerable now that starts can be unattended and remote (the MCP
surface), so an unverifiable scope refuses the start.

These tests pin the two helpers directly: a fetch failure or non-200 is a 503,
and a malformed RoE timezone is a named 400 rather than a silent pass.
"""
import urllib.error

import pytest
from fastapi import HTTPException

import api


class _FakeResponse:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# --- _fetch_project_for_preflight: fail closed -------------------------------

def test_fetch_refuses_with_503_when_webapp_unreachable(monkeypatch):
    def _boom(*a, **kw):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", _boom)
    with pytest.raises(HTTPException) as ei:
        api._fetch_project_for_preflight("proj-1")
    assert ei.value.status_code == 503
    # The message must name the unreachable dependency, not be generic.
    assert "webapp" in str(ei.value.detail).lower()


def test_fetch_refuses_with_503_on_timeout(monkeypatch):
    def _timeout(*a, **kw):
        raise TimeoutError("timed out")

    monkeypatch.setattr("urllib.request.urlopen", _timeout)
    with pytest.raises(HTTPException) as ei:
        api._fetch_project_for_preflight("proj-1")
    assert ei.value.status_code == 503


def test_fetch_refuses_with_503_on_non_200(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda *a, **kw: _FakeResponse(500, b"{}")
    )
    with pytest.raises(HTTPException) as ei:
        api._fetch_project_for_preflight("proj-1")
    assert ei.value.status_code == 503
    assert "500" in str(ei.value.detail)


def test_fetch_returns_project_on_200(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *a, **kw: _FakeResponse(200, b'{"targetDomain": "example.com"}'),
    )
    assert api._fetch_project_for_preflight("proj-1") == {
        "targetDomain": "example.com"
    }


def test_fetch_never_swallows_its_own_refusal(monkeypatch):
    """The 503 must not be re-wrapped by the broad except into another 503 with
    a misleading 'unreachable' message when the webapp actually answered."""
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda *a, **kw: _FakeResponse(404, b"{}")
    )
    with pytest.raises(HTTPException) as ei:
        api._fetch_project_for_preflight("proj-1")
    assert "unreachable" not in str(ei.value.detail).lower()
    assert "404" in str(ei.value.detail)


# --- _check_roe_time_window --------------------------------------------------

def test_roe_check_is_a_noop_when_no_window_is_configured():
    """With no window there is nothing to gate on, whatever else is set."""
    api._check_roe_time_window({})
    api._check_roe_time_window({"roeGlobalMaxRps": 3})
    # The stored column contributes nothing: the flag is DERIVED, and a window
    # that is off is not a limit.
    api._check_roe_time_window({"roeEnabled": True})


def test_the_window_gates_on_itself_rather_than_on_a_stored_flag():
    """A window switched on IS a live limit, with no second switch to agree.

    This is the case the derivation exists for: `roeEnabled` used to have to be
    true as well, so a configured window with the flag off silently gated
    nothing. The 403 below is what stops that being possible.
    """
    with pytest.raises(HTTPException) as ei:
        api._check_roe_time_window(
            {
                # Deliberately FALSE, and deliberately ignored.
                "roeEnabled": False,
                "roeTimeWindowEnabled": True,
                "roeTimeWindowTimezone": "UTC",
                "roeTimeWindowDays": [],
            }
        )
    assert ei.value.status_code == 403


def test_malformed_timezone_is_a_named_400_not_a_silent_pass():
    with pytest.raises(HTTPException) as ei:
        api._check_roe_time_window(
            {
                "roeTimeWindowEnabled": True,
                "roeTimeWindowTimezone": "Not/AZone",
            }
        )
    assert ei.value.status_code == 400
    assert "Not/AZone" in str(ei.value.detail)


def test_disallowed_day_raises_403():
    # Every day disallowed, so the assertion holds whichever day it runs on.
    with pytest.raises(HTTPException) as ei:
        api._check_roe_time_window(
            {
                "roeTimeWindowEnabled": True,
                "roeTimeWindowTimezone": "UTC",
                "roeTimeWindowDays": [],
            }
        )
    assert ei.value.status_code == 403
    assert "not allowed on" in str(ei.value.detail)


def test_outside_time_window_raises_403():
    all_days = [
        "monday", "tuesday", "wednesday", "thursday",
        "friday", "saturday", "sunday",
    ]
    with pytest.raises(HTTPException) as ei:
        api._check_roe_time_window(
            {
                "roeTimeWindowEnabled": True,
                "roeTimeWindowTimezone": "UTC",
                "roeTimeWindowDays": all_days,
                # An empty window: nothing can be inside it.
                "roeTimeWindowStartTime": "23:59",
                "roeTimeWindowEndTime": "00:00",
            }
        )
    assert ei.value.status_code == 403


def test_inside_a_full_day_window_passes():
    all_days = [
        "monday", "tuesday", "wednesday", "thursday",
        "friday", "saturday", "sunday",
    ]
    api._check_roe_time_window(
        {
            "roeTimeWindowEnabled": True,
            "roeTimeWindowTimezone": "UTC",
            "roeTimeWindowDays": all_days,
            "roeTimeWindowStartTime": "00:00",
            "roeTimeWindowEndTime": "23:59",
        }
    )


# --- the endpoints actually refuse, and spawn nothing --------------------------

class _SpyContainerManager:
    """Records whether a container was ever asked for."""

    def __init__(self):
        self.start_calls = 0

    async def start_recon(self, **kw):
        self.start_calls += 1
        raise AssertionError("a container was spawned despite an unverified scope")

    async def start_partial_recon(self, **kw):
        self.start_calls += 1
        raise AssertionError("a container was spawned despite an unverified scope")


def _unreachable_webapp(monkeypatch):
    def _boom(*a, **kw):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", _boom)


def test_start_recon_refuses_and_spawns_nothing_when_scope_unverifiable(monkeypatch):
    import asyncio

    from models import ReconStartRequest

    spy = _SpyContainerManager()
    monkeypatch.setattr(api, "container_manager", spy)
    _unreachable_webapp(monkeypatch)

    req = ReconStartRequest(
        project_id="proj-1",
        user_id="user-1",
        webapp_api_url="http://localhost:3000",
    )
    with pytest.raises(HTTPException) as ei:
        asyncio.run(api.start_recon("proj-1", req))

    assert ei.value.status_code == 503
    assert spy.start_calls == 0


def test_partial_recon_refuses_and_spawns_nothing_when_scope_unverifiable(monkeypatch):
    import asyncio

    from models import PartialReconStartRequest

    spy = _SpyContainerManager()
    monkeypatch.setattr(api, "container_manager", spy)
    _unreachable_webapp(monkeypatch)

    req = PartialReconStartRequest(
        project_id="proj-1",
        tool_id="SubdomainDiscovery",
        user_id="user-1",
        webapp_api_url="http://localhost:3000",
        graph_inputs={"domain": "example.com"},
    )
    with pytest.raises(HTTPException) as ei:
        asyncio.run(api.start_partial_recon("proj-1", req))

    assert ei.value.status_code == 503
    assert spy.start_calls == 0
