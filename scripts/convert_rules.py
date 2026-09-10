#!/usr/bin/env python3
"""Convert root Clash classical rules to Quantumult X and sing-box rule-set v3."""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ALIASES = {
    "HOST": "DOMAIN",
    "HOST-SUFFIX": "DOMAIN-SUFFIX",
    "HOST-KEYWORD": "DOMAIN-KEYWORD",
    "URL-REGEX": "DOMAIN-REGEX",
    "IP6-CIDR": "IP-CIDR6",
    "PROCESS-PATH": "PROCESS-PATH",
}
SUPPORTED = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX",
    "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "DST-PORT", "SRC-PORT",
    "PROCESS-NAME", "PROCESS-PATH",
}
QX_TYPES = {
    "DOMAIN": "HOST",
    "DOMAIN-SUFFIX": "HOST-SUFFIX",
    "DOMAIN-KEYWORD": "HOST-KEYWORD",
    "DOMAIN-REGEX": "URL-REGEX",
    "IP-CIDR": "IP-CIDR",
    "IP-CIDR6": "IP6-CIDR",
    "SRC-IP-CIDR": "SRC-IP-CIDR",
    "DST-PORT": "DST-PORT",
    "SRC-PORT": "SRC-PORT",
    "PROCESS-NAME": "PROCESS-NAME",
    "PROCESS-PATH": "PROCESS-PATH",
}
SING_FIELDS = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "DOMAIN-REGEX": "domain_regex",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr",
    "SRC-IP-CIDR": "source_ip_cidr",
    "PROCESS-NAME": "process_name",
    "PROCESS-PATH": "process_path",
}
DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}
PORT_TYPES = {"DST-PORT", "SRC-PORT"}


class ConversionError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    kind: str
    value: str
    source: str
    line: int


def strip_yaml_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        quote = value[0]
        value = value[1:-1]
        if quote == '"':
            value = bytes(value, "utf-8").decode("unicode_escape")
        else:
            value = value.replace("''", "'")
    return value.strip()


def payload_lines(text: str, source: str) -> list[tuple[int, str]]:
    """Read classical text or the simple Clash payload YAML list format.

    The payload parser intentionally accepts only a top-level `payload:` sequence of
    scalar rules. That strict subset avoids silently accepting unrelated YAML data.
    """
    lines = text.splitlines()
    payload_at = next((i for i, raw in enumerate(lines) if raw.strip() == "payload:"), None)
    if payload_at is None:
        return [(i, raw.strip()) for i, raw in enumerate(lines, 1)
                if raw.strip() and not raw.lstrip().startswith("#")]

    before = [raw for raw in lines[:payload_at] if raw.strip() and not raw.lstrip().startswith("#")]
    if before:
        raise ConversionError(f"{source}:{payload_at + 1}: payload must be the only top-level key")
    result: list[tuple[int, str]] = []
    for i, raw in enumerate(lines[payload_at + 1:], payload_at + 2):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not raw[:1].isspace() or not stripped.startswith("-"):
            raise ConversionError(f"{source}:{i}: expected an indented payload list item")
        item = stripped[1:].strip()
        if not item:
            raise ConversionError(f"{source}:{i}: empty payload item")
        result.append((i, strip_yaml_scalar(item)))
    return result


def normalize_domain(value: str, source: str, line: int) -> str:
    value = value.strip().rstrip(".")
    # Clash domain rules cannot carry a port. Repair the known :443 source typo,
    # and reject other ports rather than silently changing their meaning.
    match = re.fullmatch(r"(.+):([0-9]+)", value)
    if match:
        if match.group(2) != "443":
            raise ConversionError(f"{source}:{line}: domain contains unsupported port: {value}")
        value = match.group(1).rstrip(".")
    if not value or any(c.isspace() for c in value) or "," in value:
        raise ConversionError(f"{source}:{line}: invalid domain value: {value!r}")
    return value.lower()


def normalize_port(value: str, source: str, line: int) -> str:
    value = value.strip()
    match = re.fullmatch(r"([0-9]+)(?:[:-]([0-9]+))?", value)
    if not match:
        raise ConversionError(f"{source}:{line}: invalid port or port range: {value!r}")
    start = int(match.group(1)); end = int(match.group(2) or start)
    if not (1 <= start <= end <= 65535):
        raise ConversionError(f"{source}:{line}: port out of range: {value!r}")
    return str(start) if start == end else f"{start}:{end}"


def parse_rule(raw: str, source: str, line: int) -> Rule:
    parts = [part.strip() for part in raw.split(",")]
    if len(parts) < 2:
        raise ConversionError(f"{source}:{line}: expected TYPE,VALUE: {raw!r}")
    kind = ALIASES.get(parts[0].upper(), parts[0].upper())
    if kind not in SUPPORTED:
        raise ConversionError(f"{source}:{line}: unsupported rule type {parts[0]!r}")
    extras = [p for p in parts[2:] if p and p.lower() != "no-resolve"]
    if extras:
        raise ConversionError(f"{source}:{line}: unsupported rule options: {', '.join(extras)}")
    value = parts[1]
    if not value:
        raise ConversionError(f"{source}:{line}: empty rule value")
    if kind in DOMAIN_TYPES:
        value = normalize_domain(value, source, line)
    elif kind in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"}:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ConversionError(f"{source}:{line}: invalid CIDR {value!r}: {exc}") from exc
        expected = 6 if kind == "IP-CIDR6" else None
        if expected and network.version != expected:
            raise ConversionError(f"{source}:{line}: {kind} requires IPv6: {value!r}")
        value = str(network)
    elif kind in PORT_TYPES:
        value = normalize_port(value, source, line)
    elif kind == "DOMAIN-REGEX":
        try:
            re.compile(value)
        except re.error as exc:
            raise ConversionError(f"{source}:{line}: invalid regex {value!r}: {exc}") from exc
    return Rule(kind, value, source, line)


def parse_file(path: Path) -> tuple[list[Rule], int]:
    text = path.read_text(encoding="utf-8-sig")
    parsed = [parse_rule(raw, path.name, line) for line, raw in payload_lines(text, path.name)]
    unique: list[Rule] = []
    seen: set[tuple[str, str]] = set()
    for rule in parsed:
        key = (rule.kind, rule.value)
        if key not in seen:
            seen.add(key)
            unique.append(rule)
    return unique, len(parsed) - len(unique)


def qx_content(rules: Iterable[Rule], policy: str, source: str) -> str:
    header = [
        f"# Generated from /{source} by scripts/convert_rules.py; do not edit.",
        f"# Policy: {policy}",
    ]
    body = [f"{QX_TYPES[r.kind]},{r.value},{policy}" for r in rules]
    return "\n".join(header + body) + "\n"


def sing_rule(rule: Rule) -> dict:
    if rule.kind in PORT_TYPES:
        base = "port" if rule.kind == "DST-PORT" else "source_port"
        if ":" in rule.value:
            return {f"{base}_range": [rule.value]}
        return {base: [int(rule.value)]}
    return {SING_FIELDS[rule.kind]: [rule.value]}


def sing_content(rules: Iterable[Rule]) -> str:
    data = {"version": 3, "rules": [sing_rule(rule) for rule in rules]}
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def safe_output(root: Path, relative: str) -> Path:
    output = (root / relative).resolve()
    try:
        output.relative_to(root.resolve())
    except ValueError as exc:
        raise ConversionError(f"output escapes repository: {relative}") from exc
    return output


def convert(root: Path, config_path: Path, check: bool = False) -> int:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    entries = config.get("rulesets")
    if not isinstance(entries, list) or not entries:
        raise ConversionError("rulesets.json must contain a non-empty rulesets list")
    seen_sources: set[str] = set(); seen_names: set[str] = set(); changed = False
    for entry in entries:
        required = {"source", "name", "quantumult_x", "policy"}
        if not isinstance(entry, dict) or not required <= entry.keys():
            raise ConversionError(f"invalid mapping entry: {entry!r}")
        source = entry["source"]; name = entry["name"]
        if source in seen_sources or name in seen_names:
            raise ConversionError(f"duplicate source or name in mapping: {source}, {name}")
        seen_sources.add(source); seen_names.add(name)
        source_path = safe_output(root, source)
        if source_path.parent != root.resolve():
            raise ConversionError(f"source must be in repository root: {source}")
        if not source_path.is_file():
            raise ConversionError(f"missing source file: {source}")
        rules, duplicates = parse_file(source_path)
        if not rules:
            raise ConversionError(f"source contains no rules: {source}")
        outputs = {
            safe_output(root, entry["quantumult_x"]): qx_content(rules, entry["policy"], source),
            safe_output(root, f"sing-box/source/{name}.json"): sing_content(rules),
        }
        for output, content in outputs.items():
            old = output.read_text(encoding="utf-8") if output.exists() else None
            if old != content:
                changed = True
                if not check:
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text(content, encoding="utf-8", newline="\n")
        print(f"{source}: {len(rules)} rules ({duplicates} duplicates removed)")
    if check and changed:
        raise ConversionError("generated files are stale; run scripts/convert_rules.py")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--config", type=Path)
    parser.add_argument("--check", action="store_true", help="fail if generated text/JSON differs")
    args = parser.parse_args()
    root = args.root.resolve()
    config = args.config.resolve() if args.config else root / "rulesets.json"
    try:
        return convert(root, config, args.check)
    except (ConversionError, json.JSONDecodeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
