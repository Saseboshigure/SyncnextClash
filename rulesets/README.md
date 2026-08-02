# Canonical Rule Protocol — schema version 1

Each canonical file is a mapping with exactly four keys:

```yaml
schema_version: 1
name: proxy
policy: proxy
rules:
  - type: DOMAIN-SUFFIX
    value: example.com
```

`proxy.yaml` must declare `name: proxy` and `policy: proxy`; `unbreak.yaml` must
declare `name: unbreak` and `policy: direct`. Rules are ordered and may contain
only `type`, `value`, and—where required—`representations`.

Version 1 accepts:

- `DOMAIN-SUFFIX` with a valid DNS domain.
- `DOMAIN-KEYWORD` with a non-empty keyword and an explicit Passwall representation.
- `IP-CIDR` with a strict canonical IPv4 network such as `203.0.113.0/24`.

Exact duplicate rules and identical rules in opposite policies are invalid.
Generated Passwall domains and CIDRs must also remain disjoint across policies.

## Passwall representation

Passwall has no matcher equivalent to `DOMAIN-KEYWORD`. Every keyword therefore
declares all domains that Passwall may receive:

```yaml
- type: DOMAIN-KEYWORD
  value: media-cdn
  representations:
    passwall:
      domains:
        - media-cdn-special.example
      numbered_domains:
        - format: "media-cdn{n}.example"
          start: 1
          end: 20
```

`domains` is an explicit list. `numbered_domains` accepts only a valid domain
format containing exactly one `{n}` plus an inclusive, non-negative integer
range. At least one of the two lists must produce a domain.

The generator never derives an expansion from the keyword. Missing mappings,
unknown fields, invalid ranges, unsupported rule types, or routing conflicts
stop the complete generation before the destination directory is replaced.
