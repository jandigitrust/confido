"""Installed-wheel checks for the Python client boundary."""

import unittest
from pathlib import Path

import confido_client


POLICY = (
    Path(__file__).resolve().parents[3]
    / "verifier/tests/fixtures/verifier-policy-v2.json"
).read_bytes()


class ClientApiTests(unittest.TestCase):
    def test_wheel_exposes_both_client_and_verifier_build_identity(self):
        info = confido_client.build_info()
        self.assertEqual(info["client"]["core"]["pipeline_revision"], 2)
        self.assertEqual(info["client"]["wrapper"]["version"], "0.2.0")
        self.assertEqual(info["wrapper"]["version"], "0.2.0")

    def test_invalid_origin_or_policy_fails_before_network(self):
        for origin in ("http://example.test", "https://example.test/other"):
            with self.assertRaises(RuntimeError):
                confido_client.appraise(origin, POLICY)
        with self.assertRaises(RuntimeError):
            confido_client.appraise("https://example.test", b"{}")
