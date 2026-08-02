# Repository Guidelines

## Source of Truth

- `rulesets/proxy.yaml` and `rulesets/unbreak.yaml` are the only maintained rule data.
- Root Clash files and every file on the `generated` branch are generated artifacts. Never edit them as rule sources.
- `rulesets/README.md` owns schema version 1 and Passwall expansion semantics.

## Maintenance Flow

1. Edit the appropriate canonical file without reordering unrelated rules.
2. Install exactly the dependency versions in `requirements.lock`.
3. Run `python tools/rules.py validate` and `python -m unittest discover -s tests -v`.
4. If sing-box v1.13.15 is available, run `python tools/rules.py generate --output output`.
5. Open a pull request and inspect the CI preview artifact. Publication happens only after merge to main.

Never add guessed conversion, silent omission, alternate source, legacy merge, or best-effort output. A target that cannot represent a canonical rule must have an explicit representation in the canonical rule or fail validation.

## Canonical Style

- Preserve rule order and the spelling/case of existing canonical values.
- Version 1 supports only `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, and IPv4 `IP-CIDR`.
- A `DOMAIN-KEYWORD` must include a non-empty explicit Passwall representation.
- Passwall numbered expansion uses exactly one `{n}` placeholder plus inclusive integer `start` and `end`.
- Keep YAML at two-space indentation and Python at four-space indentation.

## Verification and Publication

- Tests must cover the external generator interface and observable artifacts, not private implementation details.
- Negative tests must prove malformed or unrepresentable state fails without partial output.
- GitHub Actions used by workflows must stay pinned to full commit SHAs.
- `scripts/install_ci_sing_box.sh` pins both sing-box version and release archive SHA-256.
- PR workflows are read-only. Only the main-branch publication workflow may write root compatibility files or the `generated` branch.
- Build and test do not authorize manual publication, push, release, or unrelated repository changes.

## Commit and Pull Request Style

- Follow the existing emoji plus conventional type/scope style, for example `✨ feat(rules): add example.com`.
- Describe the routing intent, canonical rules changed, affected generated formats, and evidence used for any explicit expansion.
- Preserve unrelated staged, unstaged, and untracked work.
