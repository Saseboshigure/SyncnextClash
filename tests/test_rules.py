from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

from tools import rules


class RulesTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.rulesets = self.root / "rulesets"
        fixture_rulesets = Path(__file__).parent / "fixtures" / "rulesets"
        shutil.copytree(fixture_rulesets, self.rulesets)

    def read_documents(self) -> dict[str, dict]:
        return {
            filename: yaml.safe_load((self.rulesets / filename).read_text(encoding="utf-8"))
            for filename in rules.EXPECTED_RULESETS
        }

    def write_document(self, filename: str, document: dict) -> None:
        (self.rulesets / filename).write_text(
            yaml.safe_dump(document, sort_keys=False),
            encoding="utf-8",
        )

    def assert_invalid(self, expected: str) -> None:
        with self.assertRaisesRegex(rules.RuleError, expected):
            rules.load_rulesets(self.rulesets)

    def test_current_canonical_rules_validate(self) -> None:
        proxy, unbreak = rules.load_rulesets(rules.DEFAULT_RULESETS_DIR)
        self.assertTrue(proxy.rules)
        self.assertTrue(unbreak.rules)

    def test_passwall_expansion_is_complete_and_split_by_value_type(self) -> None:
        artifacts = {artifact.relative_path: artifact for artifact in rules.build_text_artifacts(self.rulesets)}
        direct_hosts = artifacts["passwall/direct_host"].content.decode().splitlines()
        proxy_hosts = artifacts["passwall/proxy_host"].content.decode().splitlines()
        self.assertEqual(["direct.example", "cdn-special.example", "cdn1.example", "cdn2.example"], direct_hosts)
        self.assertEqual(["proxy.example"], proxy_hosts)
        self.assertEqual(1, artifacts["passwall/direct_ip"].records)
        self.assertEqual(b"\n", artifacts["passwall/proxy_ip"].content)

    def test_quantumult_x_policy_and_type_mapping(self) -> None:
        artifacts = {artifact.relative_path: artifact.content.decode() for artifact in rules.build_text_artifacts(self.rulesets)}
        self.assertIn("host-suffix, proxy.example, proxy\n", artifacts["quantumult-x/proxy.list"])
        self.assertIn("host-keyword, cdn, direct\n", artifacts["quantumult-x/unbreak.list"])
        self.assertIn("ip-cidr, 192.0.2.0/24, direct\n", artifacts["quantumult-x/unbreak.list"])

    def test_clash_and_classical_adapters_have_golden_output(self) -> None:
        artifacts = {artifact.relative_path: artifact.content.decode() for artifact in rules.build_text_artifacts(self.rulesets)}
        clash_proxy = "payload:\n  - DOMAIN-SUFFIX,proxy.example\n"
        classical_proxy = "DOMAIN-SUFFIX,proxy.example\n"
        self.assertEqual(clash_proxy, artifacts["proxy-classical.yaml"])
        for directory in ("mihomo", "stash"):
            self.assertEqual(clash_proxy, artifacts[f"{directory}/proxy-classical.yaml"])
        for directory in ("surge", "loon", "shadowrocket"):
            self.assertEqual(classical_proxy, artifacts[f"{directory}/proxy.list"])

    def test_sing_box_keeps_one_headless_rule_per_canonical_rule(self) -> None:
        import json

        artifacts = {artifact.relative_path: artifact.content for artifact in rules.build_text_artifacts(self.rulesets)}
        proxy = json.loads(artifacts["sing-box/proxy.json"])
        unbreak = json.loads(artifacts["sing-box/unbreak.json"])
        self.assertEqual(1, proxy["version"])
        self.assertEqual(1, len(proxy["rules"]))
        self.assertEqual(3, len(unbreak["rules"]))
        self.assertEqual({"domain_keyword": ["cdn"]}, unbreak["rules"][1])

    def test_build_is_deterministic(self) -> None:
        first = rules.build_text_artifacts(self.rulesets)
        second = rules.build_text_artifacts(self.rulesets)
        self.assertEqual(first, second)

    def test_missing_required_key_fails(self) -> None:
        documents = self.read_documents()
        del documents["proxy.yaml"]["policy"]
        self.write_document("proxy.yaml", documents["proxy.yaml"])
        self.assert_invalid("missing keys: policy")

    def test_unknown_rule_key_fails(self) -> None:
        documents = self.read_documents()
        documents["proxy.yaml"]["rules"][0]["fallback"] = "direct"
        self.write_document("proxy.yaml", documents["proxy.yaml"])
        self.assert_invalid("unknown keys: fallback")

    def test_unknown_rule_type_fails(self) -> None:
        documents = self.read_documents()
        documents["proxy.yaml"]["rules"][0]["type"] = "DOMAIN-REGEX"
        self.write_document("proxy.yaml", documents["proxy.yaml"])
        self.assert_invalid("unsupported rule type")

    def test_invalid_domain_fails(self) -> None:
        documents = self.read_documents()
        documents["proxy.yaml"]["rules"][0]["value"] = "not a domain"
        self.write_document("proxy.yaml", documents["proxy.yaml"])
        self.assert_invalid("invalid domain")

    def test_invalid_cidr_fails(self) -> None:
        documents = self.read_documents()
        documents["unbreak.yaml"]["rules"][2]["value"] = "192.0.2.1/24"
        self.write_document("unbreak.yaml", documents["unbreak.yaml"])
        self.assert_invalid("invalid IPv4 CIDR")

    def test_keyword_without_passwall_mapping_fails(self) -> None:
        documents = self.read_documents()
        del documents["unbreak.yaml"]["rules"][1]["representations"]
        self.write_document("unbreak.yaml", documents["unbreak.yaml"])
        self.assert_invalid("expected mapping")

    def test_invalid_numbered_template_fails(self) -> None:
        documents = self.read_documents()
        numbered = documents["unbreak.yaml"]["rules"][1]["representations"]["passwall"]["numbered_domains"][0]
        numbered["format"] = "lzcdn.com"
        self.write_document("unbreak.yaml", documents["unbreak.yaml"])
        self.assert_invalid("expected exactly one.*placeholder")

    def test_duplicate_canonical_rule_fails(self) -> None:
        documents = self.read_documents()
        documents["proxy.yaml"]["rules"].append(documents["proxy.yaml"]["rules"][0].copy())
        self.write_document("proxy.yaml", documents["proxy.yaml"])
        self.assert_invalid("duplicate canonical rule")

    def test_cross_collection_conflict_fails(self) -> None:
        documents = self.read_documents()
        documents["proxy.yaml"]["rules"].append({"type": "DOMAIN-SUFFIX", "value": "direct.example"})
        self.write_document("proxy.yaml", documents["proxy.yaml"])
        self.assert_invalid("routing conflict between proxy and unbreak")

    def test_passwall_expansion_conflict_fails(self) -> None:
        documents = self.read_documents()
        documents["proxy.yaml"]["rules"].append({"type": "DOMAIN-SUFFIX", "value": "cdn2.example"})
        self.write_document("proxy.yaml", documents["proxy.yaml"])
        self.assert_invalid("Passwall routing conflict")

    def test_failed_generation_does_not_create_output(self) -> None:
        output = self.root / "generated"
        with self.assertRaisesRegex(rules.RuleError, "missing required command"):
            rules.generate(output, self.rulesets, "/definitely/missing/sing-box")
        self.assertFalse(output.exists())

    def test_compile_failure_preserves_existing_output(self) -> None:
        output = self.root / "generated"
        output.mkdir()
        sentinel = output / "sentinel"
        sentinel.write_text("keep", encoding="utf-8")
        (output / "manifest.json").write_text(
            '{"generator":"SyncnextClash/tools/rules.py"}\n',
            encoding="utf-8",
        )
        fake = self.root / "sing-box"
        fake.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = version ]; then\n"
            "  echo 'sing-box version 1.13.15'\n"
            "  exit 0\n"
            "fi\n"
            "echo 'intentional compile failure' >&2\n"
            "exit 1\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        with self.assertRaisesRegex(rules.RuleError, "intentional compile failure"):
            rules.generate(output, self.rulesets, str(fake))
        self.assertEqual("keep", sentinel.read_text(encoding="utf-8"))

    def test_non_generated_output_is_never_replaced(self) -> None:
        output = self.root / "not-generated"
        output.mkdir()
        sentinel = output / "sentinel"
        sentinel.write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(rules.RuleError, "missing generated manifest"):
            rules.generate(output, self.rulesets, "/definitely/missing/sing-box")
        self.assertEqual("keep", sentinel.read_text(encoding="utf-8"))

    def test_repo_and_home_ancestors_are_unsafe_output_targets(self) -> None:
        for target in (rules.REPO_ROOT, Path.home(), Path(rules.REPO_ROOT.anchor)):
            with self.assertRaisesRegex(rules.RuleError, "refusing broad target"):
                rules._validated_output_dir(target)


if __name__ == "__main__":
    unittest.main()
