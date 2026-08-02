#!/usr/bin/env python3
"""Validate canonical Syncnext rules and render every supported client format."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as error:  # pragma: no cover - exercised by the CLI environment
    raise SystemExit(
        "missing required dependency: install requirements.lock before running tools/rules.py"
    ) from error


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULESETS_DIR = REPO_ROOT / "rulesets"
SUPPORTED_SCHEMA_VERSION = 1
SUPPORTED_RULE_TYPES = ("DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR")
EXPECTED_RULESETS = {
    "proxy.yaml": ("proxy", "proxy"),
    "unbreak.yaml": ("unbreak", "direct"),
}
SING_BOX_VERSION = "1.13.15"
GENERATOR_ID = "SyncnextClash/tools/rules.py"

DOMAIN_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)


class RuleError(ValueError):
    """Raised when canonical data or generated output violates the protocol."""


@dataclass(frozen=True)
class NumberedDomain:
    format: str
    start: int
    end: int

    def expand(self) -> tuple[str, ...]:
        return tuple(self.format.replace("{n}", str(number)) for number in range(self.start, self.end + 1))


@dataclass(frozen=True)
class PasswallRepresentation:
    domains: tuple[str, ...]
    numbered_domains: tuple[NumberedDomain, ...]

    def expand_domains(self) -> tuple[str, ...]:
        expanded = list(self.domains)
        for numbered in self.numbered_domains:
            expanded.extend(numbered.expand())
        return tuple(expanded)


@dataclass(frozen=True)
class Rule:
    type: str
    value: str
    passwall: PasswallRepresentation | None = None


@dataclass(frozen=True)
class RuleSet:
    name: str
    policy: str
    rules: tuple[Rule, ...]


@dataclass(frozen=True)
class Artifact:
    relative_path: str
    content: bytes
    records: int


def _require_mapping(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuleError(f"malformed {context}: expected mapping")
    return value


def _require_exact_keys(mapping: dict[str, Any], allowed: set[str], required: set[str], context: str) -> None:
    missing = sorted(required - mapping.keys())
    unknown = sorted(mapping.keys() - allowed)
    if missing:
        raise RuleError(f"malformed {context}: missing keys: {', '.join(missing)}")
    if unknown:
        raise RuleError(f"malformed {context}: unknown keys: {', '.join(unknown)}")


def _require_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise RuleError(f"malformed {context}: expected non-empty string")
    return value


def _validate_domain(value: str, context: str) -> None:
    if not DOMAIN_RE.fullmatch(value):
        raise RuleError(f"malformed {context}: invalid domain: {value}")


def _validate_keyword(value: str, context: str) -> None:
    if any(character.isspace() for character in value) or "," in value:
        raise RuleError(f"malformed {context}: invalid domain keyword: {value}")


def _parse_numbered_domain(raw: Any, context: str) -> NumberedDomain:
    mapping = _require_mapping(raw, context)
    _require_exact_keys(mapping, {"format", "start", "end"}, {"format", "start", "end"}, context)
    format_value = _require_string(mapping["format"], f"{context}.format")
    if format_value.count("{n}") != 1 or "{" in format_value.replace("{n}", "") or "}" in format_value.replace("{n}", ""):
        raise RuleError(f"malformed {context}.format: expected exactly one {{n}} placeholder")
    start = mapping["start"]
    end = mapping["end"]
    if isinstance(start, bool) or not isinstance(start, int) or start < 0:
        raise RuleError(f"malformed {context}.start: expected non-negative integer")
    if isinstance(end, bool) or not isinstance(end, int) or end < start:
        raise RuleError(f"malformed {context}.end: expected integer greater than or equal to start")
    numbered = NumberedDomain(format=format_value, start=start, end=end)
    for domain in numbered.expand():
        _validate_domain(domain, context)
    return numbered


def _parse_passwall(raw: Any, context: str) -> PasswallRepresentation:
    mapping = _require_mapping(raw, context)
    _require_exact_keys(mapping, {"domains", "numbered_domains"}, set(), context)
    raw_domains = mapping.get("domains", [])
    raw_numbered = mapping.get("numbered_domains", [])
    if not isinstance(raw_domains, list):
        raise RuleError(f"malformed {context}.domains: expected list")
    if not isinstance(raw_numbered, list):
        raise RuleError(f"malformed {context}.numbered_domains: expected list")
    domains = tuple(_require_string(item, f"{context}.domains") for item in raw_domains)
    for domain in domains:
        _validate_domain(domain, context)
    numbered = tuple(
        _parse_numbered_domain(item, f"{context}.numbered_domains[{index}]")
        for index, item in enumerate(raw_numbered)
    )
    representation = PasswallRepresentation(domains=domains, numbered_domains=numbered)
    if not representation.expand_domains():
        raise RuleError(f"malformed {context}: at least one explicit Passwall domain is required")
    return representation


def _parse_rule(raw: Any, context: str) -> Rule:
    mapping = _require_mapping(raw, context)
    _require_exact_keys(mapping, {"type", "value", "representations"}, {"type", "value"}, context)
    rule_type = _require_string(mapping["type"], f"{context}.type")
    value = _require_string(mapping["value"], f"{context}.value")
    if rule_type not in SUPPORTED_RULE_TYPES:
        raise RuleError(f"malformed {context}.type: unsupported rule type: {rule_type}")

    passwall: PasswallRepresentation | None = None
    representations = mapping.get("representations")
    if rule_type == "DOMAIN-KEYWORD":
        reps_mapping = _require_mapping(representations, f"{context}.representations")
        _require_exact_keys(reps_mapping, {"passwall"}, {"passwall"}, f"{context}.representations")
        passwall = _parse_passwall(reps_mapping["passwall"], f"{context}.representations.passwall")
        _validate_keyword(value, f"{context}.value")
    else:
        if representations is not None:
            raise RuleError(f"malformed {context}.representations: only DOMAIN-KEYWORD accepts target representations")
        if rule_type == "DOMAIN-SUFFIX":
            _validate_domain(value, f"{context}.value")
        else:
            try:
                network = ipaddress.ip_network(value, strict=True)
            except ValueError as error:
                raise RuleError(f"malformed {context}.value: invalid IPv4 CIDR: {value}") from error
            if network.version != 4:
                raise RuleError(f"malformed {context}.value: IP-CIDR v1 accepts IPv4 only: {value}")
    return Rule(type=rule_type, value=value, passwall=passwall)


def _load_ruleset(path: Path, expected_name: str, expected_policy: str) -> RuleSet:
    if not path.is_file():
        raise RuleError(f"missing canonical artifact: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise RuleError(f"malformed canonical YAML: {path}: {error}") from error
    mapping = _require_mapping(raw, str(path))
    _require_exact_keys(
        mapping,
        {"schema_version", "name", "policy", "rules"},
        {"schema_version", "name", "policy", "rules"},
        str(path),
    )
    if mapping["schema_version"] != SUPPORTED_SCHEMA_VERSION:
        raise RuleError(
            f"malformed {path}.schema_version: expected {SUPPORTED_SCHEMA_VERSION}, got {mapping['schema_version']!r}"
        )
    if mapping["name"] != expected_name:
        raise RuleError(f"malformed {path}.name: expected {expected_name}, got {mapping['name']!r}")
    if mapping["policy"] != expected_policy:
        raise RuleError(f"malformed {path}.policy: expected {expected_policy}, got {mapping['policy']!r}")
    raw_rules = mapping["rules"]
    if not isinstance(raw_rules, list) or not raw_rules:
        raise RuleError(f"malformed {path}.rules: expected non-empty list")
    rules = tuple(_parse_rule(item, f"{path}.rules[{index}]") for index, item in enumerate(raw_rules))
    seen: set[tuple[str, str]] = set()
    for rule in rules:
        identity = (rule.type, rule.value.casefold())
        if identity in seen:
            raise RuleError(f"duplicate canonical rule in {path}: {rule.type},{rule.value}")
        seen.add(identity)
    return RuleSet(name=expected_name, policy=expected_policy, rules=rules)


def load_rulesets(rulesets_dir: Path = DEFAULT_RULESETS_DIR) -> tuple[RuleSet, RuleSet]:
    loaded = {
        name: _load_ruleset(rulesets_dir / filename, name, policy)
        for filename, (name, policy) in EXPECTED_RULESETS.items()
    }
    proxy = loaded["proxy"]
    unbreak = loaded["unbreak"]
    proxy_rules = {(rule.type, rule.value.casefold()) for rule in proxy.rules}
    for rule in unbreak.rules:
        if (rule.type, rule.value.casefold()) in proxy_rules:
            raise RuleError(f"routing conflict between proxy and unbreak: {rule.type},{rule.value}")
    _validate_passwall_conflicts(proxy, unbreak)
    return proxy, unbreak


def _stable_unique(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        identity = value.casefold()
        if identity not in seen:
            seen.add(identity)
            result.append(value)
    return tuple(result)


def _passwall_values(ruleset: RuleSet) -> tuple[tuple[str, ...], tuple[str, ...]]:
    domains: list[str] = []
    cidrs: list[str] = []
    for rule in ruleset.rules:
        if rule.type == "DOMAIN-SUFFIX":
            domains.append(rule.value)
        elif rule.type == "IP-CIDR":
            cidrs.append(rule.value)
        else:
            if rule.passwall is None:
                raise RuleError(f"missing Passwall representation: {ruleset.name}:{rule.type},{rule.value}")
            domains.extend(rule.passwall.expand_domains())
    return _stable_unique(domains), _stable_unique(cidrs)


def _validate_passwall_conflicts(proxy: RuleSet, unbreak: RuleSet) -> None:
    proxy_domains, proxy_cidrs = _passwall_values(proxy)
    direct_domains, direct_cidrs = _passwall_values(unbreak)
    domain_conflicts = sorted({value.casefold() for value in proxy_domains} & {value.casefold() for value in direct_domains})
    cidr_conflicts = sorted(set(proxy_cidrs) & set(direct_cidrs))
    if domain_conflicts:
        raise RuleError(f"Passwall routing conflict for domains: {', '.join(domain_conflicts)}")
    if cidr_conflicts:
        raise RuleError(f"Passwall routing conflict for CIDRs: {', '.join(cidr_conflicts)}")


def _text_artifact(path: str, lines: Iterable[str], records: int | None = None) -> Artifact:
    materialized = tuple(lines)
    content = "\n".join(materialized) + "\n"
    return Artifact(path, content.encode("utf-8"), len(materialized) if records is None else records)


def _clash_artifact(path: str, ruleset: RuleSet) -> Artifact:
    return _text_artifact(path, ("payload:", *(f"  - {rule.type},{rule.value}" for rule in ruleset.rules)), len(ruleset.rules))


def _classical_artifact(path: str, ruleset: RuleSet) -> Artifact:
    return _text_artifact(path, (f"{rule.type},{rule.value}" for rule in ruleset.rules))


def _quantumult_x_artifact(path: str, ruleset: RuleSet) -> Artifact:
    type_mapping = {
        "DOMAIN-SUFFIX": "host-suffix",
        "DOMAIN-KEYWORD": "host-keyword",
        "IP-CIDR": "ip-cidr",
    }
    return _text_artifact(
        path,
        (f"{type_mapping[rule.type]}, {rule.value}, {ruleset.policy}" for rule in ruleset.rules),
    )


def _sing_box_artifact(path: str, ruleset: RuleSet) -> Artifact:
    field_mapping = {
        "DOMAIN-SUFFIX": "domain_suffix",
        "DOMAIN-KEYWORD": "domain_keyword",
        "IP-CIDR": "ip_cidr",
    }
    document = {
        "version": 1,
        "rules": [{field_mapping[rule.type]: [rule.value]} for rule in ruleset.rules],
    }
    content = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    return Artifact(path, content, len(ruleset.rules))


def build_text_artifacts(rulesets_dir: Path = DEFAULT_RULESETS_DIR) -> tuple[Artifact, ...]:
    proxy, unbreak = load_rulesets(rulesets_dir)
    artifacts: list[Artifact] = [
        _clash_artifact("proxy-classical.yaml", proxy),
        _clash_artifact("Unbreak-classical.yaml", unbreak),
    ]
    for directory in ("mihomo", "stash"):
        artifacts.extend(
            (
                _clash_artifact(f"{directory}/proxy-classical.yaml", proxy),
                _clash_artifact(f"{directory}/Unbreak-classical.yaml", unbreak),
            )
        )
    for directory in ("surge", "loon", "shadowrocket"):
        artifacts.extend(
            (
                _classical_artifact(f"{directory}/proxy.list", proxy),
                _classical_artifact(f"{directory}/unbreak.list", unbreak),
            )
        )
    artifacts.extend(
        (
            _quantumult_x_artifact("quantumult-x/proxy.list", proxy),
            _quantumult_x_artifact("quantumult-x/unbreak.list", unbreak),
            _sing_box_artifact("sing-box/proxy.json", proxy),
            _sing_box_artifact("sing-box/unbreak.json", unbreak),
        )
    )
    proxy_domains, proxy_cidrs = _passwall_values(proxy)
    direct_domains, direct_cidrs = _passwall_values(unbreak)
    artifacts.extend(
        (
            _text_artifact("passwall/proxy_host", proxy_domains),
            _text_artifact("passwall/proxy_ip", proxy_cidrs),
            _text_artifact("passwall/direct_host", direct_domains),
            _text_artifact("passwall/direct_ip", direct_cidrs),
        )
    )
    return tuple(artifacts)


def _run_checked(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, check=True, capture_output=True, text=True)
    except FileNotFoundError as error:
        raise RuleError(f"missing required command: {command[0]}") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() or error.stdout.strip() or str(error)
        raise RuleError(f"command failed: {' '.join(command)}: {detail}") from error


def _resolve_sing_box(executable: str | None) -> str:
    resolved = executable or shutil.which("sing-box")
    if not resolved:
        raise RuleError("missing required command: sing-box v1.13.15 is required to generate .srs artifacts")
    version = _run_checked([resolved, "version"]).stdout
    if f"sing-box version {SING_BOX_VERSION}" not in version:
        raise RuleError(f"invalid sing-box version: required {SING_BOX_VERSION}, got {version.strip()!r}")
    return resolved


def _source_commit(repo_root: Path) -> str:
    commit = _run_checked(["git", "-C", str(repo_root), "rev-parse", "HEAD"]).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RuleError(f"invalid source commit: {commit!r}")
    return commit


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _validated_output_dir(output_dir: Path) -> Path:
    if output_dir.is_symlink():
        raise RuleError(f"unsafe output directory: symbolic links are not accepted: {output_dir}")
    resolved = output_dir.resolve()
    protected = (REPO_ROOT.resolve(), Path.home().resolve())
    if resolved == Path(resolved.anchor) or any(root == resolved or root.is_relative_to(resolved) for root in protected):
        raise RuleError(f"unsafe output directory: refusing broad target: {resolved}")
    if resolved.exists():
        if not resolved.is_dir():
            raise RuleError(f"unsafe output directory: expected directory: {resolved}")
        entries = tuple(resolved.iterdir())
        if entries:
            manifest_path = resolved / "manifest.json"
            if not manifest_path.is_file():
                raise RuleError(f"unsafe output directory: missing generated manifest: {resolved}")
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as error:
                raise RuleError(f"unsafe output directory: invalid generated manifest: {resolved}: {error}") from error
            if not isinstance(manifest, dict) or manifest.get("generator") != GENERATOR_ID:
                raise RuleError(f"unsafe output directory: invalid generator identity: {resolved}")
    return resolved


def _normalized_sing_box(document: Any, context: str) -> dict[str, Any]:
    mapping = _require_mapping(document, context)
    _require_exact_keys(mapping, {"version", "rules"}, {"version", "rules"}, context)
    if mapping["version"] != 1:
        raise RuleError(f"malformed {context}.version: expected 1")
    raw_rules = mapping["rules"]
    if not isinstance(raw_rules, list):
        raise RuleError(f"malformed {context}.rules: expected list")
    normalized_rules = []
    for index, raw_rule in enumerate(raw_rules):
        rule = _require_mapping(raw_rule, f"{context}.rules[{index}]")
        if len(rule) != 1:
            raise RuleError(f"malformed {context}.rules[{index}]: expected one matcher")
        field, raw_values = next(iter(rule.items()))
        values = [raw_values] if isinstance(raw_values, str) else raw_values
        if not isinstance(values, list) or not values or not all(isinstance(value, str) for value in values):
            raise RuleError(f"malformed {context}.rules[{index}].{field}: expected string or non-empty string list")
        normalized_rules.append({field: values})
    return {"version": 1, "rules": normalized_rules}


def _verify_srs(executable: str, source: Path, binary: Path) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        decompiled = Path(temporary) / "decompiled.json"
        _run_checked([executable, "rule-set", "decompile", "--output", str(decompiled), str(binary)])
        try:
            source_document = json.loads(source.read_text(encoding="utf-8"))
            binary_document = json.loads(decompiled.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as error:
            raise RuleError(f"invalid sing-box round-trip output for {binary}: {error}") from error
    if _normalized_sing_box(source_document, str(source)) != _normalized_sing_box(binary_document, str(binary)):
        raise RuleError(f"sing-box semantic round-trip mismatch: {binary}")


def generate(output_dir: Path, rulesets_dir: Path = DEFAULT_RULESETS_DIR, sing_box: str | None = None) -> None:
    output_dir = _validated_output_dir(output_dir)
    executable = _resolve_sing_box(sing_box)
    artifacts = list(build_text_artifacts(rulesets_dir))
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=output_dir.parent))
    try:
        record_counts: dict[str, int] = {}
        for artifact in artifacts:
            path = staging / artifact.relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(artifact.content)
            record_counts[artifact.relative_path] = artifact.records
        for name in ("proxy", "unbreak"):
            source = staging / "sing-box" / f"{name}.json"
            target = staging / "sing-box" / f"{name}.srs"
            _run_checked([executable, "rule-set", "compile", "--output", str(target), str(source)])
            _verify_srs(executable, source, target)
            record_counts[f"sing-box/{name}.srs"] = record_counts[f"sing-box/{name}.json"]

        source_files = {}
        for filename in EXPECTED_RULESETS:
            path = rulesets_dir / filename
            source_files[f"rulesets/{filename}"] = _sha256(path.read_bytes())
        artifact_entries = {}
        for path in sorted(item for item in staging.rglob("*") if item.is_file()):
            relative = path.relative_to(staging).as_posix()
            artifact_entries[relative] = {
                "records": record_counts[relative],
                "sha256": _sha256(path.read_bytes()),
            }
        manifest = {
            "generator": GENERATOR_ID,
            "schema_version": SUPPORTED_SCHEMA_VERSION,
            "source_commit": _source_commit(REPO_ROOT),
            "source_files": source_files,
            "artifacts": artifact_entries,
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if output_dir.exists():
            shutil.rmtree(output_dir)
        staging.rename(output_dir)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def check_generated(rulesets_dir: Path = DEFAULT_RULESETS_DIR) -> None:
    artifacts = {artifact.relative_path: artifact.content for artifact in build_text_artifacts(rulesets_dir)}
    for filename in ("proxy-classical.yaml", "Unbreak-classical.yaml"):
        actual_path = REPO_ROOT / filename
        if not actual_path.is_file():
            raise RuleError(f"missing generated root artifact: {actual_path}")
        if actual_path.read_bytes() != artifacts[filename]:
            raise RuleError(f"stale generated root artifact: {filename}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rulesets-dir", type=Path, default=DEFAULT_RULESETS_DIR)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate", help="validate canonical rule sets")
    generate_parser = subparsers.add_parser("generate", help="generate every supported artifact atomically")
    generate_parser.add_argument("--output", type=Path, required=True)
    generate_parser.add_argument("--sing-box", help="path to the required sing-box v1.13.15 executable")
    subparsers.add_parser("check-generated", help="verify main-branch root Clash artifacts")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "validate":
            proxy, unbreak = load_rulesets(args.rulesets_dir)
            print(f"validated proxy={len(proxy.rules)} unbreak={len(unbreak.rules)}")
        elif args.command == "generate":
            generate(args.output, args.rulesets_dir, args.sing_box)
            print(f"generated artifacts in {args.output}")
        else:
            check_generated(args.rulesets_dir)
            print("generated root artifacts are current")
    except (RuleError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
