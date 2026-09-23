"""
Tests for NVIDIA NIM and Arliai provider integration.

Covers:
  - parse_model_provider() prefix routing for nvidia/<model> and arliai/<model>
  - setup_llm() NVIDIA + Arliai branches (kwarg validation + ChatOpenAI wiring)
  - fetch_nvidia_models() / fetch_arliai_models() success path, filter, failure
  - fetch_all_models() aggregator wires "nvidia" and "arliai" providerTypes
  - Existing providers unaffected

Run with: python -m pytest tests/test_nvidia_arliai_providers.py -v
"""

import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

from orchestrator_helpers.llm_setup import parse_model_provider, setup_llm
from orchestrator_helpers.model_providers import (
    fetch_nvidia_models,
    fetch_arliai_models,
    fetch_all_models,
)


# ---------------------------------------------------------------------------
# Unit: parse_model_provider
# ---------------------------------------------------------------------------
class TestParseModelProviderNvidiaArliai(unittest.TestCase):
    def test_nvidia_prefix(self):
        self.assertEqual(
            parse_model_provider("nvidia/nemotron-3-super-120b-a12b"),
            ("nvidia", "nemotron-3-super-120b-a12b"),
        )
        self.assertEqual(
            parse_model_provider("nvidia/nemotron-3-ultra-550b-a55b"),
            ("nvidia", "nemotron-3-ultra-550b-a55b"),
        )

    def test_arliai_prefix(self):
        self.assertEqual(
            parse_model_provider("arliai/DeepSeek-V4-Flash-0731"),
            ("arliai", "DeepSeek-V4-Flash-0731"),
        )
        self.assertEqual(
            parse_model_provider("arliai/Fastest"),
            ("arliai", "Fastest"),
        )

    def test_nvidia_prefix_with_unknown_id_passes_through(self):
        self.assertEqual(
            parse_model_provider("nvidia/nemotron-9000-ultra"),
            ("nvidia", "nemotron-9000-ultra"),
        )

    def test_arliai_prefix_with_unknown_id_passes_through(self):
        self.assertEqual(
            parse_model_provider("arliai/future-merge-3000"),
            ("arliai", "future-merge-3000"),
        )

    def test_existing_prefixes_still_route(self):
        """Regression: ensure adding nvidia/arliai didn't break other prefixes."""
        self.assertEqual(
            parse_model_provider("custom/abc"),
            ("custom", "abc"),
        )
        self.assertEqual(
            parse_model_provider("deepseek/deepseek-flash"),
            ("deepseek", "deepseek-flash"),
        )
        self.assertEqual(
            parse_model_provider("openrouter/anthropic/claude-sonnet-4"),
            ("openrouter", "anthropic/claude-sonnet-4"),
        )
        self.assertEqual(
            parse_model_provider("claude-opus-4-7"),
            ("anthropic", "claude-opus-4-7"),
        )
        self.assertEqual(
            parse_model_provider("gpt-4o"),
            ("openai", "gpt-4o"),
        )

    def test_bare_nvidia_id_routes_to_openai(self):
        """Without the nvidia/ prefix, the contract treats it as OpenAI."""
        self.assertEqual(
            parse_model_provider("nemotron-3-super-120b-a12b"),
            ("openai", "nemotron-3-super-120b-a12b"),
        )

    def test_bare_arliai_id_routes_to_openai(self):
        """Without the arliai/ prefix, the contract treats it as OpenAI."""
        self.assertEqual(
            parse_model_provider("DeepSeek-V4-Flash-0731"),
            ("openai", "DeepSeek-V4-Flash-0731"),
        )


# ---------------------------------------------------------------------------
# Unit: setup_llm (NVIDIA branch)
# ---------------------------------------------------------------------------
class TestSetupLlmNvidia(unittest.TestCase):
    def test_missing_key_raises(self):
        with self.assertRaises(ValueError) as ctx:
            setup_llm("nvidia/nemotron-3-super-120b-a12b")
        self.assertIn("NVIDIA NIM API key", str(ctx.exception))

    def test_empty_string_key_raises(self):
        with self.assertRaises(ValueError):
            setup_llm("nvidia/nemotron-3-super-120b-a12b", nvidia_api_key="")

    @patch("orchestrator_helpers.llm_setup.ChatOpenAI")
    def test_builds_chatopenai_with_correct_base_url(self, mock_chat):
        mock_chat.return_value = MagicMock()
        llm = setup_llm(
            "nvidia/nemotron-3-super-120b-a12b",
            nvidia_api_key="nvapi-test",
        )
        mock_chat.assert_called_once()
        kwargs = mock_chat.call_args.kwargs
        # NIM's chat/completions requires the FULL catalogue id: the routing
        # prefix stripped by parse_model_provider carried the org namespace
        # ('nvidia/...'), so it must reach the API untouched.
        self.assertEqual(kwargs.get("model"), "nvidia/nemotron-3-super-120b-a12b")
        self.assertEqual(kwargs.get("api_key"), "nvapi-test")
        self.assertEqual(kwargs.get("base_url"), "https://integrate.api.nvidia.com/v1")
        self.assertEqual(kwargs.get("temperature"), 0)
        self.assertIs(llm, mock_chat.return_value)

    @patch("orchestrator_helpers.llm_setup.ChatOpenAI")
    def test_bare_id_is_re_prefixed_for_api(self, mock_chat):
        """A bare model_identifier (pre-prefix-convention row) must be re-prefixed."""
        mock_chat.return_value = MagicMock()
        setup_llm(
            "nvidia/nemotron-3-super-120b-a12b",
            nvidia_api_key="nvapi-test",
        )
        kwargs = mock_chat.call_args.kwargs
        self.assertNotEqual(kwargs.get("model"), "nemotron-3-super-120b-a12b")
        self.assertTrue(kwargs.get("model").startswith("nvidia/"))

    @patch("orchestrator_helpers.llm_setup.ChatOpenAI")
    def test_other_provider_unaffected_when_nvidia_key_passed(self, mock_chat):
        """Regression: providing nvidia_api_key while resolving OpenAI should not pollute kwargs."""
        mock_chat.return_value = MagicMock()
        setup_llm(
            "gpt-4o-mini",
            openai_api_key="sk-openai",
            nvidia_api_key="nvapi-test",
        )
        kwargs = mock_chat.call_args.kwargs
        self.assertEqual(kwargs.get("api_key"), "sk-openai")
        self.assertNotIn("base_url", kwargs)


# ---------------------------------------------------------------------------
# Unit: setup_llm (Arliai branch)
# ---------------------------------------------------------------------------
class TestSetupLlmArliai(unittest.TestCase):
    def test_missing_key_raises(self):
        with self.assertRaises(ValueError) as ctx:
            setup_llm("arliai/DeepSeek-V4-Flash-0731")
        self.assertIn("Arliai API key", str(ctx.exception))

    def test_empty_string_key_raises(self):
        with self.assertRaises(ValueError):
            setup_llm("arliai/DeepSeek-V4-Flash-0731", arliai_api_key="")

    @patch("orchestrator_helpers.llm_setup.ChatOpenAI")
    def test_builds_chatopenai_with_correct_base_url_and_no_temperature(self, mock_chat):
        """Arliai serves community fine-tunes; several hosted merges reject
        temperature=0 with a permanent 400, so the branch must OMIT the
        temperature kwarg entirely rather than send a default."""
        mock_chat.return_value = MagicMock()
        llm = setup_llm(
            "arliai/DeepSeek-V4-Flash-0731",
            arliai_api_key="arli-test",
        )
        mock_chat.assert_called_once()
        kwargs = mock_chat.call_args.kwargs
        self.assertEqual(kwargs.get("model"), "DeepSeek-V4-Flash-0731")
        self.assertEqual(kwargs.get("api_key"), "arli-test")
        self.assertEqual(kwargs.get("base_url"), "https://api.arliai.com/v1")
        self.assertNotIn("temperature", kwargs)
        self.assertIs(llm, mock_chat.return_value)

    @patch("orchestrator_helpers.llm_setup.ChatOpenAI")
    def test_other_provider_unaffected_when_arliai_key_passed(self, mock_chat):
        """Regression: providing arliai_api_key while resolving OpenAI should not pollute kwargs."""
        mock_chat.return_value = MagicMock()
        setup_llm(
            "gpt-4o-mini",
            openai_api_key="sk-openai",
            arliai_api_key="arli-test",
        )
        kwargs = mock_chat.call_args.kwargs
        self.assertEqual(kwargs.get("api_key"), "sk-openai")
        self.assertNotIn("base_url", kwargs)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Unit: fetch_nvidia_models
# ---------------------------------------------------------------------------
class TestFetchNvidiaModels(unittest.TestCase):
    def setUp(self):
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())

    def test_empty_key_returns_empty(self):
        result = _run(fetch_nvidia_models(api_key=""))
        self.assertEqual(result, [])

    @patch("orchestrator_helpers.model_providers.httpx.AsyncClient")
    def test_success_path_filters_and_prefixes(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={
            "data": [
                {"id": "nvidia/nemotron-3-super-120b-a12b"},
                {"id": "meta/llama-3.2-11b-vision-instruct"},
                # Non-chat catalogue entries must be dropped.
                {"id": "nvidia/embed-qa-4"},
                {"id": "nvidia/llama-guard-4-12b"},
                {"id": "nvidia/nemotron-4-340b-reward"},
                {"id": "snowflake/arctic-embed-l"},
            ]
        })

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client_cls.return_value.__aexit__.return_value = None

        result = _run(fetch_nvidia_models(api_key="nvapi-test"))

        ids = [m["id"] for m in result]
        # All ids prefixed with nvidia/ for routing.
        self.assertTrue(all(i.startswith("nvidia/") for i in ids))
        # Chat models present.
        self.assertIn("nvidia/nvidia/nemotron-3-super-120b-a12b", ids)
        self.assertIn("nvidia/meta/llama-3.2-11b-vision-instruct", ids)
        # Non-chat models excluded.
        self.assertNotIn("nvidia/nvidia/embed-qa-4", ids)
        self.assertNotIn("nvidia/nvidia/llama-guard-4-12b", ids)
        self.assertNotIn("nvidia/nvidia/nemotron-4-340b-reward", ids)
        self.assertNotIn("nvidia/snowflake/arctic-embed-l", ids)
        # Sort order is reverse-lexical (newest first).
        self.assertEqual(ids, sorted(ids, reverse=True))
        # Description tags every entry as NVIDIA NIM.
        self.assertTrue(all(m["description"] == "NVIDIA NIM" for m in result))

    @patch("orchestrator_helpers.model_providers.httpx.AsyncClient")
    def test_http_error_returns_empty(self, mock_client_cls):
        """The NIM catalogue has no hardcoded fallback: an unreachable
        endpoint returns no entries (matching the DeepSeek fetcher)."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("connection refused"))
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client_cls.return_value.__aexit__.return_value = None

        result = _run(fetch_nvidia_models(api_key="nvapi-test"))
        self.assertEqual(result, [])

    @patch("orchestrator_helpers.model_providers.httpx.AsyncClient")
    def test_empty_data_returns_empty(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={"data": []})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client_cls.return_value.__aexit__.return_value = None

        result = _run(fetch_nvidia_models(api_key="nvapi-test"))
        self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# Unit: fetch_arliai_models
# ---------------------------------------------------------------------------
class TestFetchArliaiModels(unittest.TestCase):
    def setUp(self):
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())

    def test_empty_key_returns_empty(self):
        result = _run(fetch_arliai_models(api_key=""))
        self.assertEqual(result, [])

    @patch("orchestrator_helpers.model_providers.httpx.AsyncClient")
    def test_success_path_keeps_fastest_and_excludes_nonchat(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={
            "data": [
                {"id": "Fastest", "context_length": 0},
                {"id": "DeepSeek-V4-Flash-0731", "context_length": 524288},
                {"id": "Gemma-4-31B-Aura-4o-Rebirth-Merged", "context_length": 262144},
                # Non-chat catalogue entries must be dropped.
                {"id": "Gemma-4-31B-AssGuard", "context_length": 262144},
                {"id": "Gemma-4-31B-SDFT-Heretic-RP", "context_length": 262144},
            ]
        })

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client_cls.return_value.__aexit__.return_value = None

        result = _run(fetch_arliai_models(api_key="arli-test"))

        ids = [m["id"] for m in result]
        # All ids prefixed with arliai/ for routing.
        self.assertTrue(all(i.startswith("arliai/") for i in ids))
        # The 'Fastest' alias is kept (ctx 0 -> None) — it is a chat alias.
        self.assertIn("arliai/Fastest", ids)
        fastest = next(m for m in result if m["id"] == "arliai/Fastest")
        self.assertIsNone(fastest["context_length"])
        # Chat merges present with their real context lengths.
        self.assertIn("arliai/DeepSeek-V4-Flash-0731", ids)
        ds = next(m for m in result if m["id"] == "arliai/DeepSeek-V4-Flash-0731")
        self.assertEqual(ds["context_length"], 524288)
        # Non-chat entries excluded.
        self.assertNotIn("arliai/Gemma-4-31B-AssGuard", ids)
        self.assertNotIn("arliai/Gemma-4-31B-SDFT-Heretic-RP", ids)
        # Sort order is reverse-lexical.
        self.assertEqual(ids, sorted(ids, reverse=True))
        # Description tags every entry as Arliai.
        self.assertTrue(all(m["description"] == "Arliai" for m in result))

    @patch("orchestrator_helpers.model_providers.httpx.AsyncClient")
    def test_http_error_returns_empty(self, mock_client_cls):
        """No hardcoded fallback: an unreachable endpoint returns no entries."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("connection refused"))
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client_cls.return_value.__aexit__.return_value = None

        result = _run(fetch_arliai_models(api_key="arli-test"))
        self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# Unit: fetch_all_models aggregator wiring
# ---------------------------------------------------------------------------
class TestFetchAllModelsWiringNvidiaArliai(unittest.TestCase):
    def setUp(self):
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())

    @patch("orchestrator_helpers.model_providers.fetch_nvidia_models", new_callable=AsyncMock)
    def test_nvidia_provider_type_is_dispatched(self, mock_fetch):
        mock_fetch.return_value = [
            {"id": "nvidia/nemotron-3-super-120b-a12b", "name": "nemotron-3-super-120b-a12b",
             "context_length": None, "description": "NVIDIA NIM"}
        ]

        providers = [{
            "id": "abc",
            "providerType": "nvidia",
            "name": "My NIM",
            "apiKey": "nvapi-test",
        }]
        result = _run(fetch_all_models(providers=providers))

        self.assertIn("NVIDIA NIM (My NIM)", result)
        models = result["NVIDIA NIM (My NIM)"]
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0]["id"], "nvidia/nemotron-3-super-120b-a12b")
        mock_fetch.assert_called_once_with(api_key="nvapi-test")

    @patch("orchestrator_helpers.model_providers.fetch_arliai_models", new_callable=AsyncMock)
    def test_arliai_provider_type_is_dispatched(self, mock_fetch):
        mock_fetch.return_value = [
            {"id": "arliai/DeepSeek-V4-Flash-0731", "name": "DeepSeek-V4-Flash-0731",
             "context_length": 524288, "description": "Arliai"}
        ]

        providers = [{
            "id": "def",
            "providerType": "arliai",
            "name": "Team Arliai",
            "apiKey": "arli-test",
        }]
        result = _run(fetch_all_models(providers=providers))

        self.assertIn("Arliai (Team Arliai)", result)
        models = result["Arliai (Team Arliai)"]
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0]["id"], "arliai/DeepSeek-V4-Flash-0731")
        mock_fetch.assert_called_once_with(api_key="arli-test")

    @patch("orchestrator_helpers.model_providers.fetch_nvidia_models", new_callable=AsyncMock)
    @patch("orchestrator_helpers.model_providers.fetch_arliai_models", new_callable=AsyncMock)
    def test_both_providers_can_coexist(self, mock_arliai, mock_nvidia):
        """Regression: NVIDIA and Arliai dispatch should work simultaneously."""
        mock_nvidia.return_value = [
            {"id": "nvidia/nemotron-3-super-120b-a12b", "name": "nemotron-3-super-120b-a12b",
             "context_length": None, "description": "NVIDIA NIM"}
        ]
        mock_arliai.return_value = [
            {"id": "arliai/DeepSeek-V4-Flash-0731", "name": "DeepSeek-V4-Flash-0731",
             "context_length": 524288, "description": "Arliai"}
        ]

        providers = [
            {"id": "p1", "providerType": "nvidia", "name": "My NIM", "apiKey": "k1"},
            {"id": "p2", "providerType": "arliai", "name": "My Arliai", "apiKey": "k2"},
        ]
        result = _run(fetch_all_models(providers=providers))

        self.assertIn("NVIDIA NIM (My NIM)", result)
        self.assertIn("Arliai (My Arliai)", result)
        self.assertEqual(len(result["NVIDIA NIM (My NIM)"]), 1)
        self.assertEqual(len(result["Arliai (My Arliai)"]), 1)

    def test_unknown_provider_type_is_ignored(self):
        result = _run(fetch_all_models(providers=[{
            "providerType": "arliai_typo",
            "id": "x",
            "name": "y",
        }]))
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()
