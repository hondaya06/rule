# rule

The Clash classical files in the repository root are the **only rule source**.
Generated files under `QuantumultX/`, `sing-box/source/`, and `sing-box/srs/`
must not be edited manually.

## Mapping

`rulesets.json` explicitly maps each root source to its rule-set name, Quantumult X
output path, and Quantumult X policy. To add a rule set, add its root source file
and one mapping entry. Keep policy names aligned with the policy groups in your
client configuration.

| Source | Quantumult X output / policy | sing-box outputs |
| --- | --- | --- |
| `AI.list` | `QuantumultX/AI.list` / `AI` | `AI.json`, `AI.srs` |
| `F1TV.list` | `QuantumultX/F1TV.list` / `F1TV` | `F1TV.json`, `F1TV.srs` |
| `Home.list` | `QuantumultX/Home.list` / `direct` | `Home.json`, `Home.srs` |
| `direct.list` | `QuantumultX/direct.list` / `direct` | `direct.json`, `direct.srs` |
| `proxy.list` | `QuantumultX/proxy.list` / `proxy` | `proxy.json`, `proxy.srs` |
| `reject.list` | `QuantumultX/reject.list` / `reject` | `reject.json`, `reject.srs` |
| `SpeedtestInternational.yaml` | `QuantumultX/SpeedtestInternational.list` / `SpeedtestInternational` | `SpeedtestInternational.json`, `SpeedtestInternational.srs` |

The converter accepts ordinary classical text and a strict Clash `payload:` YAML
list. It supports `DOMAIN`/`HOST`, `DOMAIN-SUFFIX`/`HOST-SUFFIX`,
`DOMAIN-KEYWORD`, `DOMAIN-REGEX`/`URL-REGEX`, `IP-CIDR`,
`IP-CIDR6`/`IP6-CIDR`, `SRC-IP-CIDR`, `DST-PORT`, `SRC-PORT`,
`PROCESS-NAME`, and `PROCESS-PATH`. `no-resolve` is ignored. Any unknown rule or
option fails conversion instead of being silently lost.

`DOMAIN-REGEX` and `URL-REGEX` are emitted as Quantumult X `URL-REGEX` and
sing-box `domain_regex`. Domain values ending in the erroneous `:443` are repaired;
other embedded ports fail validation. Normalized duplicate rules are removed.

## Local verification

```sh
python3 scripts/convert_rules.py
python3 -m unittest discover -s tests -v
python3 -m json.tool sing-box/source/AI.json >/dev/null
python3 scripts/convert_rules.py --check
```

GitHub Actions repeats these checks, downloads the pinned official sing-box binary,
verifies its SHA-256, compiles every JSON source to `.srs`, and commits changed
generated files with `[skip ci]` to prevent an infinite workflow loop.

This repository does not generate or modify client subscription configuration.
