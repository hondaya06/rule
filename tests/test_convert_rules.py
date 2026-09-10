import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("convert_rules", Path(__file__).parents[1] / "scripts/convert_rules.py")
mod = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)


class ConvertRulesTests(unittest.TestCase):
    def test_text_aliases_no_resolve_port_cleanup_and_dedup(self):
        text = """# comment
HOST-SUFFIX,Example.COM:443
DOMAIN-SUFFIX,example.com
IP6-CIDR,2001:db8::1/64,no-resolve
DST-PORT,8000-8002
PROCESS-PATH,/usr/bin/example
"""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "rules.list"
            path.write_text(text)
            rules, duplicates = mod.parse_file(path)
        self.assertEqual(duplicates, 1)
        self.assertEqual([(r.kind, r.value) for r in rules], [
            ("DOMAIN-SUFFIX", "example.com"),
            ("IP-CIDR6", "2001:db8::/64"),
            ("DST-PORT", "8000:8002"),
            ("PROCESS-PATH", "/usr/bin/example"),
        ])

    def test_payload_yaml_and_sing_box_v3(self):
        text = """# metadata
payload:
  - DOMAIN,one.example
  - 'SRC-PORT,53'
  - URL-REGEX,^api\\.example$
"""
        items = mod.payload_lines(text, "payload.yaml")
        rules = [mod.parse_rule(raw, "payload.yaml", line) for line, raw in items]
        data = json.loads(mod.sing_content(rules))
        self.assertEqual(data["version"], 3)
        self.assertEqual(data["rules"], [
            {"domain": ["one.example"]},
            {"source_port": [53]},
            {"domain_regex": [r"^api\.example$"]},
        ])

    def test_all_supported_types_render_for_both_targets(self):
        raw_rules = [
            "DOMAIN,exact.example",
            "DOMAIN-SUFFIX,suffix.example",
            "DOMAIN-KEYWORD,needle",
            r"DOMAIN-REGEX,^regex\\.example$",
            "IP-CIDR,192.0.2.7/24,no-resolve",
            "IP-CIDR6,2001:db8::1/64",
            "SRC-IP-CIDR,198.51.100.8/24",
            "DST-PORT,443",
            "SRC-PORT,1000:1002",
            "PROCESS-NAME,example",
            "PROCESS-PATH,/opt/example/bin/app",
        ]
        rules = [mod.parse_rule(raw, "all.list", i) for i, raw in enumerate(raw_rules, 1)]
        qx = mod.qx_content(rules, "TestPolicy", "all.list")
        self.assertIn("HOST,exact.example,TestPolicy", qx)
        self.assertIn("HOST-SUFFIX,suffix.example,TestPolicy", qx)
        self.assertIn("HOST-KEYWORD,needle,TestPolicy", qx)
        self.assertIn(r"URL-REGEX,^regex\\.example$,TestPolicy", qx)
        self.assertIn("IP-CIDR,192.0.2.0/24,TestPolicy", qx)
        self.assertIn("IP6-CIDR,2001:db8::/64,TestPolicy", qx)
        self.assertIn("SRC-IP-CIDR,198.51.100.0/24,TestPolicy", qx)
        data = json.loads(mod.sing_content(rules))
        self.assertEqual(data["rules"], [
            {"domain": ["exact.example"]},
            {"domain_suffix": ["suffix.example"]},
            {"domain_keyword": ["needle"]},
            {"domain_regex": [r"^regex\\.example$"]},
            {"ip_cidr": ["192.0.2.0/24"]},
            {"ip_cidr": ["2001:db8::/64"]},
            {"source_ip_cidr": ["198.51.100.0/24"]},
            {"port": [443]},
            {"source_port_range": ["1000:1002"]},
            {"process_name": ["example"]},
            {"process_path": ["/opt/example/bin/app"]},
        ])

    def test_unknown_rule_fails(self):
        with self.assertRaisesRegex(mod.ConversionError, "unsupported rule type"):
            mod.parse_rule("GEOIP,CN", "bad.list", 7)

    def test_non_443_domain_port_fails(self):
        with self.assertRaisesRegex(mod.ConversionError, "unsupported port"):
            mod.parse_rule("DOMAIN,example.com:8443", "bad.list", 1)

    def test_payload_rejects_other_top_level_data(self):
        with self.assertRaisesRegex(mod.ConversionError, "only top-level key"):
            mod.payload_lines("name: bad\npayload:\n  - DOMAIN,a.example\n", "bad.yaml")


if __name__ == "__main__":
    unittest.main()
