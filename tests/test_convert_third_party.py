import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from convert_third_party import ConversionError, convert, convert_text


class ThirdPartyTests(unittest.TestCase):
    def test_policy_dedup_wildcard_and_or_semantics(self):
        data, report = convert_text('HOST-SUFFIX,EXAMPLE.com,Proxy\nDOMAIN-SUFFIX,example.com,Proxy\nHOST-WILDCARD,youtube.*.*,YouTube\nIP-CIDR,192.0.2.7/24,Proxy,no-resolve\nIP6-CIDR,2001:db8::1/64,Proxy', 'sample', lambda n: [])
        self.assertEqual(report['input_rules'], 5)
        fields = {next(iter(r)): next(iter(r.values())) for r in data['rules']}
        self.assertEqual(fields['domain_suffix'], ['example.com'])
        self.assertEqual(fields['ip_cidr'], ['192.0.2.0/24', '2001:db8::/64'])
        self.assertTrue(all(len(r) == 1 for r in data['rules']))
        regex = fields['domain_regex'][0]
        self.assertTrue(re.fullmatch(regex, 'youtube.co.uk'))
        self.assertFalse(re.fullmatch(regex, 'notyoutube.co.uk'))
        self.assertFalse(re.fullmatch(regex, 'youtube.com'))

    def test_asn_and_user_agent(self):
        data, report = convert_text('IP-ASN,20473,OpenAI\nUSER-AGENT,YouTube*,YouTube', 'sample', lambda n: ['192.0.2.1/24', '192.0.2.0/24'])
        self.assertEqual(data['rules'], [{'ip_cidr': ['192.0.2.0/24']}])
        self.assertEqual(report['asn'], ['20473'])
        self.assertEqual(report['skipped'][0]['line'], 2)

    def test_invalid_and_unsupported_fail_closed(self):
        for text in ('GEOIP,CN,Direct', 'URL-REGEX,^https://example,Proxy', 'IP-CIDR,invalid,Proxy', 'HOST,a.example,Proxy,bogus', 'IP-ASN,0,Proxy', 'HOST,,Proxy', '<html>error</html>', '# empty', 'USER-AGENT,Only*,Proxy'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                convert_text(text, 'bad', lambda n: [])
        with self.assertRaisesRegex(ConversionError, 'empty ASN'):
            convert_text('IP-ASN,123,Proxy', 'bad', lambda n: [])

    def fixture(self, root):
        manifest = {'rulesets': [
            {'name': 'limbopro-first', 'url': 'https://raw.githubusercontent.com/a/b/main/first', 'min_rules': 1},
            {'name': 'blackmatrix7-second', 'url': 'https://raw.githubusercontent.com/a/b/main/second', 'min_rules': 1},
        ]}
        (root / 'third-party-rulesets.json').write_text(json.dumps(manifest))
        return manifest

    def test_failure_preserves_outputs_and_cache(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.fixture(root)
            convert(root, fetch=lambda u: 'HOST,old.example,Proxy')
            before = {str(p): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            def bad_fetch(url):
                return 'HOST,new.example,Proxy' if url.endswith('first') else 'GEOIP,CN,Proxy'
            with self.assertRaises(ConversionError):
                convert(root, fetch=bad_fetch)
            self.assertEqual(before, {str(p): p.read_bytes() for p in root.rglob('*') if p.is_file()})

    def test_check_is_offline_and_detects_changes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.fixture(root)
            convert(root, fetch=lambda u: 'HOST,a.example,Proxy')
            def no_network(url):
                self.fail('check must never use network')
            convert(root, check=True, fetch=no_network)
            (root / 'sing-box/source/limbopro-first.json').write_text('{}')
            with self.assertRaisesRegex(ConversionError, 'stale'):
                convert(root, check=True, fetch=no_network)

    def test_minimum_count_and_namespace(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manifest = self.fixture(root)
            manifest['rulesets'][0]['min_rules'] = 5
            (root / 'third-party-rulesets.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ConversionError, 'expected at least'):
                convert(root, fetch=lambda u: 'HOST,a.example,Proxy')
            self.assertFalse((root / 'sing-box').exists())
            manifest['rulesets'][0]['name'] = '../direct'
            (root / 'third-party-rulesets.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ConversionError, 'invalid third-party mapping'):
                convert(root, fetch=lambda u: 'HOST,a.example,Proxy')

    def test_removal_preserves_custom_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manifest = self.fixture(root)
            convert(root, fetch=lambda u: 'HOST,a.example,Proxy')
            custom = root / 'sing-box/source/direct.json'
            custom.write_text('custom')
            manifest['rulesets'].pop()
            (root / 'third-party-rulesets.json').write_text(json.dumps(manifest))
            convert(root, fetch=lambda u: 'HOST,a.example,Proxy')
            self.assertFalse((root / 'sing-box/source/blackmatrix7-second.json').exists())
            self.assertEqual(custom.read_text(), 'custom')


if __name__ == '__main__':
    unittest.main()
