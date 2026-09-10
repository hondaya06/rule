# rule

The Clash classical files in the repository root are the source for custom rules.
`third-party-rulesets.json` separately declares the public upstream lists converted
only to sing-box. These do not modify the custom rules or Quantumult X outputs.
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

## Third-party sing-box rules

The existing **Convert rules** GitHub Action also downloads and converts the ten
lists in `third-party-rulesets.json`, every six hours at minute 17 UTC and on
manual dispatch or relevant source changes. Each successful run compiles all
custom and third-party rule sets with the pinned, SHA-256-verified sing-box
1.14.0 binary, then commits changed outputs. Runs with no changes do not commit.
Scheduled runs may be delayed by GitHub.

| Upstream | Generated names (`.json` / `.srs`) |
| --- | --- |
| [limbopro/Adblock4limbo](https://github.com/limbopro/Adblock4limbo) | `limbopro-Adblock4limbo`, `limbopro-BanAD` |
| [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) | `blackmatrix7-OpenAI`, `blackmatrix7-Claude`, `blackmatrix7-Gemini`, `blackmatrix7-YouTube`, `blackmatrix7-Microsoft`, `blackmatrix7-Telegram`, `blackmatrix7-WeChat`, `blackmatrix7-ChinaMaxNoIP` |

JSON sources are in `sing-box/source/`; compiled binaries are in `sing-box/srs/`.
The source URLs and minimum accepted input counts are explicit in the manifest.
Converted rules remain attributed to their upstream authors; refer to the upstream
repositories for their respective licenses and usage terms.

Example remote rule set (change `proxy` to your actual outbound tag):

```json
{
  "type": "remote",
  "tag": "blackmatrix7-OpenAI",
  "format": "binary",
  "url": "https://raw.githubusercontent.com/hondaya06/rule/main/sing-box/srs/blackmatrix7-OpenAI.srs",
  "download_detour": "proxy",
  "update_interval": "6h"
}
```

Add this entry under `route.rule_set`, then reference its tag from a route rule
with the desired outbound/action. The upstream Quantumult X policy column is
removed; rule sets contain matches, not policy groups or node credentials.

### Conversion semantics and failure handling

- Exact domains, suffixes, keywords, IPv4 and IPv6 CIDRs are converted. Wildcard
  domains become anchored domain regexes. Duplicates are removed. Matcher families
  are separate OR branches so domain and IP matches are not accidentally ANDed.
- `USER-AGENT` has no equivalent in sing-box. Every skipped line and its reason are
  recorded in `sing-box/reports/third-party.json` (77 lines at initial generation).
- `IP-ASN` is expanded using [RIPEstat announced prefixes](https://stat.ripe.net/docs/data-api/api-endpoints/announced-prefixes.html)
  on each update. This is an announced-prefix snapshot, not an exact replacement
  for the original client's GeoIP ASN database. Prefix counts/hashes are reported.
- Unknown rule types/options, empty data, too-small lists, failed downloads and
  unsuccessful/empty ASN responses fail the run. Downloads retry three times.
  All fetched inputs are parsed before replacing local generated files. GitHub
  publishes only after tests, validation and compilation all pass, leaving the
  previously published rules available if an update fails.
- Upstream source hashes, counts and skipped lines are recorded without a changing
  build timestamp, avoiding empty time-only commits. Removing a manifest entry
  cleans that converter's prefixed outputs; custom rule sets remain untouched.
- These are routing rules only; Rewrite, MITM and JavaScript are not supported.

Local regeneration (Python 3 standard library, network required on first command):

```sh
python3 scripts/convert_third_party.py
python3 -m unittest discover -s tests -v
python3 scripts/convert_third_party.py --check
```

`--check` uses the successful download snapshots in ignored `.cache/third-party/`
and does not refetch changing upstream data. GitHub Actions compiles the generated
JSON; for a local binary use `sing-box rule-set compile --output OUTPUT.srs INPUT.json`.
