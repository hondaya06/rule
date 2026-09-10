#!/usr/bin/env python3
"""Fetch explicitly configured public QX lists and emit sing-box rule-set v3.

--check uses the last successful local download cache, never the network.
All inputs are validated before generated files are replaced.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

from convert_rules import ConversionError, parse_rule, sing_rule

PREFIXES = ('limbopro-', 'blackmatrix7-')
FIELDS = {'HOST', 'DOMAIN', 'HOST-SUFFIX', 'DOMAIN-SUFFIX',
          'HOST-KEYWORD', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP6-CIDR', 'IP-CIDR6'}

def encode(value):
    return json.dumps(value, ensure_ascii=False, indent=2) + '\n'

def download(url):
    for attempt in range(3):
        try:
            with urlopen(Request(url, headers={'User-Agent': 'hondaya06-rule-converter/1.0'}), timeout=45) as response:
                return response.read().decode('utf-8-sig')
        except (URLError, TimeoutError) as exc:
            if attempt == 2:
                raise ConversionError(f'download failed: {url}: {exc}') from exc
            time.sleep(2 ** attempt)

def valid_name(name):
    return isinstance(name, str) and name.startswith(PREFIXES) and re.fullmatch(r'[A-Za-z0-9_-]+', name)

def convert_text(text, name, resolve_asn):
    grouped = defaultdict(set)
    skipped = []
    count = 0
    asns = set()
    for number, raw in enumerate(text.splitlines(), 1):
        raw = raw.strip()
        if not raw or raw.startswith(('#', ';', '//')):
            continue
        count += 1
        parts = [p.strip() for p in raw.split(',')]
        if len(parts) not in (2, 3, 4) or not parts[1]:
            raise ConversionError(f'{name}:{number}: invalid QX rule: {raw}')
        if len(parts) == 4 and parts[3].lower() != 'no-resolve':
            raise ConversionError(f'{name}:{number}: unsupported QX option: {raw}')
        # The third QX column is the policy, not a rule-set matching condition.
        kind, value = parts[0].upper(), parts[1]
        if kind == 'USER-AGENT':
            skipped.append({'line': number, 'rule': raw, 'reason': 'sing-box has no USER-AGENT matcher'})
        elif kind == 'IP-ASN':
            if not value.isdecimal() or not 0 < int(value) <= 4294967295:
                raise ConversionError(f'{name}:{number}: invalid ASN: {value}')
            prefixes = resolve_asn(str(int(value)))
            if not prefixes:
                raise ConversionError(f'{name}:{number}: empty ASN prefix list')
            grouped['ip_cidr'].update(str(ipaddress.ip_network(p, strict=False)) for p in prefixes)
            asns.add(str(int(value)))
        elif kind in ('HOST-WILDCARD', 'DOMAIN-WILDCARD'):
            if any(c.isspace() for c in value) or any(c in value for c in '/:'):
                raise ConversionError(f'{name}:{number}: invalid wildcard domain')
            pattern = '^' + re.escape(value.lower()).replace(r'\*', '.*').replace(r'\?', '.') + '$'
            grouped['domain_regex'].add(pattern)
        elif kind in FIELDS:
            rule = parse_rule(','.join((kind, value)), name, number)
            for field, values in sing_rule(rule).items():
                grouped[field].update(values)
        else:
            raise ConversionError(f'{name}:{number}: unsupported rule type: {kind}')
    if not grouped:
        raise ConversionError(f'{name}: no convertible rules')
    # Separate matcher families: domain and IP fields in one headless rule would AND.
    rules = [{field: sorted(values)} for field, values in sorted(grouped.items())]
    return {'version': 3, 'rules': rules}, {
        'input_rules': count, 'converted_values': sum(len(v) for v in grouped.values()),
        'asn': sorted(asns), 'skipped': skipped,
    }

def convert(root, check=False, fetch=download):
    manifest = json.loads((root / 'third-party-rulesets.json').read_text())
    entries = manifest.get('rulesets')
    if not isinstance(entries, list) or not entries:
        raise ConversionError('third-party-rulesets.json requires a non-empty rulesets list')
    names = set()
    for entry in entries:
        if not isinstance(entry, dict) or not valid_name(entry.get('name')):
            raise ConversionError(f'invalid third-party mapping: {entry!r}')
        if entry['name'] in names:
            raise ConversionError('duplicate rule-set name: ' + entry['name'])
        names.add(entry['name'])
        if not entry.get('url', '').startswith('https://raw.githubusercontent.com/'):
            raise ConversionError('expected a public GitHub raw source URL')
        if not isinstance(entry.get('min_rules'), int) or entry['min_rules'] < 1:
            raise ConversionError('min_rules must be a positive integer')
    cache = root / '.cache/third-party'
    cache_updates = {}
    def source(key, url):
        path = cache / key
        text = path.read_text(encoding='utf-8') if check else fetch(url)
        cache_updates[path] = text
        return text
    asn_cache = {}
    def resolve_asn(number):
        if number not in asn_cache:
            url = 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS' + number
            payload = json.loads(source('AS' + number + '.json', url))
            if payload.get('status') != 'ok':
                raise ConversionError('RIPEstat returned unsuccessful status for AS' + number)
            values = payload['data']['prefixes']
            prefixes = sorted({str(ipaddress.ip_network(p['prefix'], strict=False)) for p in values})
            if not prefixes:
                raise ConversionError('RIPEstat returned no prefixes for AS' + number)
            asn_cache[number] = prefixes
        return asn_cache[number]
    outputs = {}
    report = {'sources': [], 'asn': {}, 'asn_note': 'RIPEstat announced-prefix snapshots; not equivalent to a GeoIP ASN database.'}
    for entry in entries:
        name = entry['name']
        text = source(name + '.list', entry['url'])
        data, info = convert_text(text, name, resolve_asn)
        if info['input_rules'] < entry['min_rules']:
            raise ConversionError(f'{name}: only {info["input_rules"]} rules; expected at least {entry["min_rules"]}')
        outputs[root / 'sing-box/source' / (name + '.json')] = encode(data)
        report['sources'].append({**entry, 'sha256': hashlib.sha256(text.encode()).hexdigest(), **info})
        print(f'{name}: {info["input_rules"]} input rules, {len(info["skipped"])} USER-AGENT skipped')
    for number, prefixes in sorted(asn_cache.items()):
        report['asn'][number] = {'prefix_count': len(prefixes), 'sha256': hashlib.sha256(encode(prefixes).encode()).hexdigest()}
    report_path = root / 'sing-box/reports/third-party.json'
    outputs[report_path] = encode(report)
    # Only remove generated files belonging to this converter's explicit namespace.
    stale = [p for folder, ext in [('source', 'json'), ('srs', 'srs')]
             for p in (root / 'sing-box' / folder).glob('*.' + ext)
             if valid_name(p.stem) and p.stem not in names]
    changed = [p for p, content in outputs.items() if not p.exists() or p.read_text(encoding='utf-8') != content]
    if check:
        if changed or stale:
            raise ConversionError('third-party generated files are stale; run scripts/convert_third_party.py')
        return
    # No writes occur on network, parser, ASN or minimum-count failure.
    for path, content in {**cache_updates, **outputs}.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(path.suffix + '.tmp')
        temp.write_text(content, encoding='utf-8', newline='\n')
        temp.replace(path)
    for path in stale:
        path.unlink()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    try:
        convert(args.root.resolve(), args.check)
        return 0
    except (ConversionError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
