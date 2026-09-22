"""What gets the engagement into the agent's system prompt, and what does not.

The gate used to be one boolean: `ROE_ENABLED`, which a person set by ticking a
box. That column is DERIVED now - the engagement's limits apply when there IS a
limit to apply - and gating the whole block on the derived value alone would
have dropped the RECORD from every project that recorded an engagement without
configuring a limit. Most projects are exactly that shape, so the regression
would have been quiet and wide: the client's name, the emergency contact and the
document excerpt would simply stop reaching the model.

So the gate is the OR of the two halves, and these tests pin each one
separately.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
for path in (str(REPO_ROOT), str(REPO_ROOT / "agentic")):
    if path not in sys.path:
        sys.path.insert(0, path)

from prompts.base import build_roe_prompt_section  # noqa: E402


def _settings(**over):
    """A `get_setting` stand-in over a dict, with the shipped fallbacks."""
    values = dict(over)

    def get_setting(key, default=None):
        return values.get(key, default)

    return get_setting


class EngagementPromptGate(unittest.TestCase):
    def test_nothing_at_all_produces_nothing(self):
        """No limits and no record is not an engagement, so there is none to describe."""
        with patch("project_settings.get_setting", _settings()):
            self.assertEqual(build_roe_prompt_section(), "")

    def test_a_live_limit_alone_produces_the_block(self):
        """A rate ceiling with no contract is still an engagement the agent must respect."""
        with patch("project_settings.get_setting", _settings(
            ROE_ENABLED=True, ROE_GLOBAL_MAX_RPS=3,
        )):
            out = build_roe_prompt_section()
        self.assertIn("RULES OF ENGAGEMENT (MANDATORY)", out)
        self.assertIn("3 requests/sec", out)

    def test_a_record_alone_produces_the_block(self):
        """The regression this file exists for.

        A project that uploaded a document and set no ceiling has
        `ROE_ENABLED` false under the derivation. Its client, its emergency
        contact and its document text must still reach the model.
        """
        with patch("project_settings.get_setting", _settings(
            ROE_ENABLED=False,
            ROE_CLIENT_NAME="Acme Ltd",
            ROE_EMERGENCY_CONTACT="+1 555 0100",
            ROE_RAW_TEXT="Testing is authorised between 1 and 30 June.",
        )):
            out = build_roe_prompt_section()
        self.assertIn("Acme Ltd", out)
        self.assertIn("+1 555 0100", out)
        self.assertIn("authorised between 1 and 30 June", out)

    def test_the_excluded_hosts_are_named_as_never_touch(self):
        with patch("project_settings.get_setting", _settings(
            ROE_ENABLED=True,
            ROE_EXCLUDED_HOSTS=["pay.target.test"],
            ROE_EXCLUDED_HOST_REASONS=["third-party processor"],
        )):
            out = build_roe_prompt_section()
        self.assertIn("EXCLUDED HOSTS (NEVER TOUCH)", out)
        self.assertIn("pay.target.test", out)
        self.assertIn("third-party processor", out)

    def test_a_zero_ceiling_is_not_reported_as_a_ceiling(self):
        """0 means NO ceiling, so printing "0 requests/sec" would be a lie."""
        with patch("project_settings.get_setting", _settings(
            ROE_ENABLED=True, ROE_GLOBAL_MAX_RPS=0, ROE_CLIENT_NAME="Acme Ltd",
        )):
            out = build_roe_prompt_section()
        self.assertNotIn("Global Rate Limit", out)


if __name__ == "__main__":
    unittest.main()
