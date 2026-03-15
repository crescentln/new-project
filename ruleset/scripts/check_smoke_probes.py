#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any


def log(msg: str) -> None:
    print(f"[smoke] {msg}")


def read_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_rules(path: pathlib.Path) -> list[str]:
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def read_openclash_rules(path: pathlib.Path) -> list[str]:
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line == "payload:" or line.startswith("#"):
            continue
        if line == "payload: []":
            return []
        if not line.startswith("- "):
            continue
        value = line[2:].strip()
        if value.startswith("'") and value.endswith("'") and len(value) >= 2:
            value = value[1:-1].replace("''", "'")
        lines.append(value)
    return lines


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Smoke probes for key ruleset outputs.")
    parser.add_argument(
        "--config",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/config/smoke_probes.json"),
        help="Smoke probe config JSON",
    )
    parser.add_argument(
        "--surge-dir",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/surge"),
        help="Directory containing surge/<category>.list outputs",
    )
    parser.add_argument(
        "--openclash-dir",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/openclash"),
        help="Directory containing openclash/<category>.yaml outputs",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = read_json(args.config)

    require_non_empty = payload.get("require_non_empty", [])
    expect_rules = payload.get("expect_rules", {})
    expect_rules_openclash = payload.get("expect_rules_openclash", {})
    forbid_rules = payload.get("forbid_rules", {})

    if not isinstance(require_non_empty, list):
        raise SystemExit("[smoke] invalid config: require_non_empty must be array")
    if not isinstance(expect_rules, dict):
        raise SystemExit("[smoke] invalid config: expect_rules must be object")
    if not isinstance(expect_rules_openclash, dict):
        raise SystemExit("[smoke] invalid config: expect_rules_openclash must be object")
    if not isinstance(forbid_rules, dict):
        raise SystemExit("[smoke] invalid config: forbid_rules must be object")

    violations: list[str] = []

    for category in require_non_empty:
        cid = str(category).strip()
        if not cid:
            continue
        path = args.surge_dir / f"{cid}.list"
        if not path.exists():
            violations.append(f"missing output file: {path}")
            continue
        rules = read_rules(path)
        if not rules:
            violations.append(f"empty ruleset: {cid}")

    for category, expected in expect_rules.items():
        cid = str(category).strip()
        if not cid:
            continue
        if not isinstance(expected, list):
            violations.append(f"invalid expected list for category: {cid}")
            continue

        path = args.surge_dir / f"{cid}.list"
        if not path.exists():
            violations.append(f"missing output file: {path}")
            continue

        rules = set(read_rules(path))
        for item in expected:
            needle = str(item).strip()
            if needle and needle not in rules:
                violations.append(f"missing expected rule in {cid}: {needle}")

    for category, expected in expect_rules_openclash.items():
        cid = str(category).strip()
        if not cid:
            continue
        if not isinstance(expected, list):
            violations.append(f"invalid openclash expected list for category: {cid}")
            continue

        path = args.openclash_dir / f"{cid}.yaml"
        if not path.exists():
            violations.append(f"missing output file: {path}")
            continue

        rules = set(read_openclash_rules(path))
        for item in expected:
            needle = str(item).strip()
            if needle and needle not in rules:
                violations.append(f"missing expected openclash rule in {cid}: {needle}")

    for category, forbidden in forbid_rules.items():
        cid = str(category).strip()
        if not cid:
            continue
        if not isinstance(forbidden, list):
            violations.append(f"invalid forbidden list for category: {cid}")
            continue

        path = args.surge_dir / f"{cid}.list"
        if not path.exists():
            violations.append(f"missing output file: {path}")
            continue

        rules = set(read_rules(path))
        for item in forbidden:
            needle = str(item).strip()
            if needle and needle in rules:
                violations.append(f"forbidden rule present in {cid}: {needle}")

    if violations:
        log(f"FAILED with {len(violations)} violation(s)")
        for msg in violations:
            log(f"- {msg}")
        return 1

    total_non_empty = len([str(x).strip() for x in require_non_empty if str(x).strip()])
    total_expected = sum(len(v) for v in expect_rules.values() if isinstance(v, list))
    total_expected_openclash = sum(len(v) for v in expect_rules_openclash.values() if isinstance(v, list))
    total_forbidden = sum(len(v) for v in forbid_rules.values() if isinstance(v, list))
    log(
        "passed: "
        f"non_empty_checks={total_non_empty} "
        f"expected_rule_checks={total_expected} "
        f"openclash_rule_checks={total_expected_openclash} "
        f"forbidden_rule_checks={total_forbidden}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
