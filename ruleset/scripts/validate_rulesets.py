#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import pathlib
import re
import sys

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_DIST_DIR = ROOT_DIR / "dist"

RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "DOMAIN-REGEX",
    "IP-CIDR",
    "IP-CIDR6",
    "PROCESS-NAME",
    "PROCESS-PATH",
    "USER-AGENT",
    "URL-REGEX",
    "GEOIP",
    "IP-ASN",
    "SRC-IP-CIDR",
    "SRC-IP-CIDR6",
    "SRC-PORT",
    "DST-PORT",
    "DEST-PORT",
    "NETWORK",
    "PROTOCOL",
}
SURGE_EXTERNAL_UNSUPPORTED_RULE_TYPES = {"DOMAIN-REGEX"}

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,62}$"
)
LABEL_RE = re.compile(r"^(?!-)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def strip_comment(line: str) -> str:
    line = line.strip()
    if not line:
        return ""
    if line.startswith(("#", "!", ";")):
        return ""
    return line


def is_domain_token(value: str) -> bool:
    if value.startswith("+."):
        value = value[2:]
    elif value.startswith("."):
        value = value[1:]
    value = value.lower()
    if DOMAIN_RE.fullmatch(value):
        return True
    # TLD-only domainset entries like ".com" are valid for suffix matching.
    return "." not in value and bool(LABEL_RE.fullmatch(value))


def validate_classical_line(line: str, path: pathlib.Path, line_no: int) -> str | None:
    if "," not in line:
        return f"{path}:{line_no} expected classical rule line with comma"
    rule_type, rest = line.split(",", 1)
    if rule_type not in RULE_TYPES:
        return f"{path}:{line_no} unknown rule type {rule_type}"
    if not rest.strip():
        return f"{path}:{line_no} empty rule payload"
    if rule_type in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-IP-CIDR6"}:
        cidr = rest.split(",", 1)[0].strip()
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return f"{path}:{line_no} invalid CIDR {cidr}"
    return None


def validate_classical_file(path: pathlib.Path) -> list[str]:
    errors: list[str] = []
    for idx, raw in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        line = strip_comment(raw)
        if not line:
            continue
        err = validate_classical_line(line, path, idx)
        if err:
            errors.append(err)
    return errors


def validate_surge_external_file(path: pathlib.Path) -> list[str]:
    errors: list[str] = []
    for idx, raw in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        line = strip_comment(raw)
        if not line or "," not in line:
            continue
        rule_type = line.split(",", 1)[0]
        if rule_type in SURGE_EXTERNAL_UNSUPPORTED_RULE_TYPES:
            errors.append(f"{path}:{idx} unsupported for Surge external ruleset: {rule_type}")
    return errors


def validate_domainset_file(path: pathlib.Path) -> list[str]:
    errors: list[str] = []
    for idx, raw in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        line = strip_comment(raw)
        if not line:
            continue
        if "," in line:
            errors.append(f"{path}:{idx} domainset line must not contain comma: {line}")
            continue
        if not is_domain_token(line):
            errors.append(f"{path}:{idx} invalid domainset token: {line}")
    return errors


def validate_ipcidr_file(path: pathlib.Path) -> list[str]:
    errors: list[str] = []
    for idx, raw in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        line = strip_comment(raw)
        if not line:
            continue
        if "," in line:
            errors.append(f"{path}:{idx} ipcidr line must not contain comma: {line}")
            continue
        try:
            ipaddress.ip_network(line, strict=False)
        except ValueError:
            errors.append(f"{path}:{idx} invalid CIDR token: {line}")
    return errors


def validate_yaml_classical_file(path: pathlib.Path) -> list[str]:
    errors: list[str] = []
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    if not lines:
        return [f"{path}:1 empty yaml file"]
    non_empty = [ln for ln in lines if ln.strip()]
    first = non_empty[0].strip() if non_empty else ""
    if first not in {"payload:", "payload: []"}:
        return [f"{path}:1 missing payload header"]
    if first == "payload: []":
        return []
    for idx, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped == "payload:":
            continue
        if not stripped.startswith("- "):
            errors.append(f"{path}:{idx} yaml payload item must start with '- '")
            continue
        value = stripped[2:].strip()
        if value.startswith("'") and value.endswith("'") and len(value) >= 2:
            value = value[1:-1].replace("''", "'")
        err = validate_classical_line(value, path, idx)
        if err:
            errors.append(err)
    return errors


def collect_files(
    dist_dir: pathlib.Path,
) -> tuple[list[pathlib.Path], list[pathlib.Path], list[pathlib.Path], list[pathlib.Path], list[pathlib.Path]]:
    classical_patterns = [
        "surge/*.list",
        "surge/non_ip/*.list",
        "surge/ip/*.list",
        "stash/*.list",
        "stash/classical/*.list",
        "compat/Clash/non_ip/*.txt",
        "compat/Clash/ip/*.txt",
        "compat/List/non_ip/*.conf",
        "compat/List/ip/*.conf",
    ]
    domainset_patterns = [
        "surge/domainset/*.conf",
        "stash/domainset/*.txt",
        "openclash/domainset/*.txt",
        "compat/Clash/domainset/*.txt",
        "compat/List/domainset/*.conf",
    ]
    ipcidr_patterns = [
        "stash/ipcidr/*.txt",
    ]
    yaml_patterns = [
        "openclash/*.yaml",
        "openclash/non_ip/*.yaml",
        "openclash/ip/*.yaml",
    ]
    surge_external_patterns = [
        "surge/*.list",
        "surge/non_ip/*.list",
        "surge/ip/*.list",
        "compat/List/non_ip/*.conf",
        "compat/List/ip/*.conf",
    ]

    classical = []
    domainset = []
    ipcidr_files = []
    yaml_files = []
    surge_external = []
    for pattern in classical_patterns:
        classical.extend(sorted(dist_dir.glob(pattern)))
    for pattern in domainset_patterns:
        domainset.extend(sorted(dist_dir.glob(pattern)))
    for pattern in ipcidr_patterns:
        ipcidr_files.extend(sorted(dist_dir.glob(pattern)))
    for pattern in yaml_patterns:
        yaml_files.extend(sorted(dist_dir.glob(pattern)))
    for pattern in surge_external_patterns:
        surge_external.extend(sorted(dist_dir.glob(pattern)))
    return classical, domainset, ipcidr_files, yaml_files, surge_external


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate generated ruleset outputs.")
    parser.add_argument("--dist-dir", type=pathlib.Path, default=DEFAULT_DIST_DIR)
    args = parser.parse_args()

    dist_dir = args.dist_dir
    if not dist_dir.exists():
        print(f"[validate] dist dir not found: {dist_dir}")
        return 1

    classical_files, domainset_files, ipcidr_files, yaml_files, surge_external_files = collect_files(dist_dir)

    errors: list[str] = []
    for path in classical_files:
        errors.extend(validate_classical_file(path))
    for path in domainset_files:
        errors.extend(validate_domainset_file(path))
    for path in ipcidr_files:
        errors.extend(validate_ipcidr_file(path))
    for path in yaml_files:
        errors.extend(validate_yaml_classical_file(path))
    for path in surge_external_files:
        errors.extend(validate_surge_external_file(path))

    print(
        "[validate] checked "
        f"classical={len(classical_files)} "
        f"domainset={len(domainset_files)} "
        f"ipcidr={len(ipcidr_files)} "
        f"yaml={len(yaml_files)} "
        f"surge_external={len(surge_external_files)}"
    )
    if errors:
        print(f"[validate] failed with {len(errors)} error(s)")
        for err in errors[:200]:
            print(err)
        if len(errors) > 200:
            print(f"... and {len(errors) - 200} more")
        return 1

    print("[validate] all outputs are format-valid for OpenClash/Surge/Stash consumption")
    return 0


if __name__ == "__main__":
    sys.exit(main())
