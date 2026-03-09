#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import pathlib
import re
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = ROOT_DIR / "config" / "sources.json"
DEFAULT_POLICY_PATH = ROOT_DIR / "config" / "policy_map.json"
DEFAULT_DIST_DIR = ROOT_DIR / "dist"
DEFAULT_CACHE_DIR = ROOT_DIR / ".cache"

USER_AGENT = "self-owned-ruleset-builder/1.0"
FETCH_MEMO: dict[str, tuple[bytes, bool]] = {}
FETCH_EVENTS: dict[str, dict[str, str]] = {}
FETCH_MODE_PRIORITY = {"network": 0, "offline_cache": 1, "fallback_cache": 2}

RULE_ORDER = {
    "DOMAIN": 0,
    "DOMAIN-SUFFIX": 1,
    "DOMAIN-KEYWORD": 2,
    "DOMAIN-WILDCARD": 3,
    "DOMAIN-REGEX": 4,
    "IP-CIDR": 5,
    "IP-CIDR6": 6,
}

ALLOWED_ACTIONS = {
    "DIRECT",
    "PROXY",
    "REJECT",
    "REJECT-DROP",
    "REJECT-NO-DROP",
    "UNSPECIFIED",
}
REJECT_ACTIONS = {"REJECT", "REJECT-DROP", "REJECT-NO-DROP"}

HOST_LINE_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1|::)\s+([^\s#;]+)")
FOOTNOTE_RE = re.compile(r"\s*\[[0-9]+\]\s*$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,62}$"
)
DUPLICATE_ARTIFACT_RE = re.compile(r"^.+ [0-9]+(?:\.[A-Za-z0-9_-]+)?$")


class BuildError(RuntimeError):
    pass


@dataclass
class SourceBuildResult:
    rules: set[str]
    used_cache: bool
    source_ref: str


def log(message: str) -> None:
    print(f"[ruleset] {message}")


def action_family(action: str) -> str:
    action = str(action).upper().strip()
    if action in REJECT_ACTIONS:
        return "REJECT"
    if action in {"DIRECT", "PROXY"}:
        return action
    return "UNSPECIFIED"


def record_fetch_event(url: str, mode: str, error: str = "") -> None:
    current = FETCH_EVENTS.get(url)
    if current is None:
        FETCH_EVENTS[url] = {"mode": mode, "error": error}
        return

    current_prio = FETCH_MODE_PRIORITY.get(current.get("mode", "network"), 0)
    mode_prio = FETCH_MODE_PRIORITY.get(mode, 0)
    if mode_prio > current_prio:
        FETCH_EVENTS[url] = {"mode": mode, "error": error}
        return

    if error and not current.get("error"):
        current["error"] = error


def build_fetch_report() -> dict[str, Any]:
    network_success_count = 0
    offline_cache_count = 0
    fallback_cache_count = 0
    fallback_events: list[dict[str, str]] = []

    for url in sorted(FETCH_EVENTS):
        item = FETCH_EVENTS[url]
        mode = item.get("mode", "network")
        if mode == "network":
            network_success_count += 1
        elif mode == "offline_cache":
            offline_cache_count += 1
        elif mode == "fallback_cache":
            fallback_cache_count += 1
            out = {"url": url}
            error = item.get("error", "")
            if error:
                out["error"] = error
            fallback_events.append(out)

    return {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "url_count": len(FETCH_EVENTS),
        "network_success_count": network_success_count,
        "offline_cache_count": offline_cache_count,
        "fallback_cache_count": fallback_cache_count,
        "fallback_events": fallback_events,
    }


def purge_duplicate_artifacts(base_dir: pathlib.Path) -> int:
    if not base_dir.exists():
        return 0

    removed = 0
    candidates = sorted(base_dir.rglob("*"), key=lambda p: len(p.parts), reverse=True)
    for path in candidates:
        if not DUPLICATE_ARTIFACT_RE.fullmatch(path.name):
            continue
        if path.is_dir():
            shutil.rmtree(path)
            removed += 1
            continue
        if path.is_file():
            path.unlink()
            removed += 1
    return removed


def normalize_domain(value: str) -> str | None:
    value = value.strip().strip("\"'").lower()
    if not value:
        return None

    if value.startswith("||"):
        value = value[2:]
    if value.startswith("*."):
        value = value[2:]
    if value.startswith("+."):
        value = value[2:]
    value = value.lstrip(".")
    value = value.split("^", 1)[0]
    value = value.split("/", 1)[0]

    if value.startswith("[") and value.endswith("]"):
        return None

    # remove optional port from hostname
    if ":" in value and value.count(":") == 1:
        host, maybe_port = value.rsplit(":", 1)
        if maybe_port.isdigit():
            value = host

    value = value.strip(".")
    if not value:
        return None

    # Filter out IP literals accidentally parsed as hostnames.
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass

    if not DOMAIN_RE.fullmatch(value):
        return None
    return value


def rule_sort_key(rule: str) -> tuple[int, str]:
    if "," in rule:
        rule_type, payload = rule.split(",", 1)
    else:
        rule_type, payload = rule, ""
    return RULE_ORDER.get(rule_type, 99), payload


def format_ip_rule(network: ipaddress._BaseNetwork) -> str:
    if isinstance(network, ipaddress.IPv4Network):
        return f"IP-CIDR,{network.with_prefixlen},no-resolve"
    return f"IP-CIDR6,{network.with_prefixlen},no-resolve"


def parse_explicit_rule(line: str) -> str | None:
    line = line.strip()
    if not line:
        return None

    if line.startswith("DOMAIN,"):
        domain = normalize_domain(line.split(",", 1)[1])
        return f"DOMAIN,{domain}" if domain else None

    if line.startswith("DOMAIN-SUFFIX,"):
        domain = normalize_domain(line.split(",", 1)[1])
        return f"DOMAIN-SUFFIX,{domain}" if domain else None

    if line.startswith("DOMAIN-KEYWORD,"):
        value = line.split(",", 1)[1].strip()
        return f"DOMAIN-KEYWORD,{value}" if value else None

    if line.startswith("DOMAIN-WILDCARD,"):
        value = line.split(",", 1)[1].strip()
        return f"DOMAIN-WILDCARD,{value}" if value else None

    if line.startswith("DOMAIN-REGEX,"):
        value = line.split(",", 1)[1].strip()
        return f"DOMAIN-REGEX,{value}" if value else None

    if line.startswith("IP-CIDR,") or line.startswith("IP-CIDR6,"):
        rule_type, rest = line.split(",", 1)
        cidr = rest.split(",", 1)[0].strip()
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return None
        return format_ip_rule(network)

    return None


def parse_domain_or_ip_token(line: str) -> str | None:
    explicit = parse_explicit_rule(line)
    if explicit:
        return explicit

    if line.startswith("+.") or line.startswith("."):
        domain = normalize_domain(line[2:] if line.startswith("+.") else line[1:])
        return f"DOMAIN-SUFFIX,{domain}" if domain else None

    if line.startswith("||"):
        domain = normalize_domain(line)
        return f"DOMAIN-SUFFIX,{domain}" if domain else None

    host_match = HOST_LINE_RE.match(line)
    if host_match:
        domain = normalize_domain(host_match.group(1))
        return f"DOMAIN,{domain}" if domain else None

    try:
        network = ipaddress.ip_network(line, strict=False)
        return format_ip_rule(network)
    except ValueError:
        pass

    domain = normalize_domain(line)
    return f"DOMAIN-SUFFIX,{domain}" if domain else None


def strip_comment(line: str) -> str:
    line = line.strip()
    if not line:
        return ""
    if line.startswith(("#", ";")):
        return ""
    if " #" in line:
        line = line.split(" #", 1)[0]
    if "\t#" in line:
        line = line.split("\t#", 1)[0]
    if " ;" in line:
        line = line.split(" ;", 1)[0]
    if "\t;" in line:
        line = line.split("\t;", 1)[0]
    return line.strip()


def parse_local_domain_text(text: str) -> set[str]:
    rules: set[str] = set()
    for raw in text.splitlines():
        line = strip_comment(raw)
        if not line:
            continue
        parsed = parse_domain_or_ip_token(line)
        if parsed:
            rules.add(parsed)
    return rules


def parse_plain_cidr_text(text: str) -> set[str]:
    rules: set[str] = set()
    for raw in text.splitlines():
        line = strip_comment(raw)
        if not line:
            continue

        explicit = parse_explicit_rule(line)
        if explicit and explicit.startswith(("IP-CIDR,", "IP-CIDR6,")):
            rules.add(explicit)
            continue

        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        rules.add(format_ip_rule(network))
    return rules


def collapse_ip_networks(networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> set[str]:
    rules: set[str] = set()
    ipv4: list[ipaddress.IPv4Network] = []
    ipv6: list[ipaddress.IPv6Network] = []

    for network in networks:
        if isinstance(network, ipaddress.IPv4Network):
            ipv4.append(network)
        else:
            ipv6.append(network)

    for network in ipaddress.collapse_addresses(ipv4):
        rules.add(format_ip_rule(network))
    for network in ipaddress.collapse_addresses(ipv6):
        rules.add(format_ip_rule(network))
    return rules


def parse_cidr_csv_first_column(text: str) -> set[str]:
    rules: set[str] = set()
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        token = line.split(",", 1)[0].strip()
        if not token:
            continue

        explicit = parse_explicit_rule(token)
        if explicit and explicit.startswith(("IP-CIDR,", "IP-CIDR6,")):
            rules.add(explicit)
            continue

        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if isinstance(network, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            networks.append(network)

    rules.update(collapse_ip_networks(networks))
    return rules


def parse_adblock_text(text: str) -> set[str]:
    rules: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(("!", "[", "#", ";")):
            continue
        if line.startswith("@@"):
            continue
        if "##" in line or "#@#" in line or "#?#" in line:
            continue

        line = line.split("$", 1)[0].strip()
        if not line:
            continue

        explicit = parse_explicit_rule(line)
        if explicit:
            rules.add(explicit)
            continue

        if line.startswith(("|http://", "|https://")):
            url = line.lstrip("|")
            try:
                hostname = urllib.parse.urlparse(url).hostname or ""
            except ValueError:
                hostname = ""
            domain = normalize_domain(hostname)
            if domain:
                rules.add(f"DOMAIN,{domain}")
            continue

        if line.startswith("||"):
            token = line[2:].split("^", 1)[0].split("/", 1)[0]
            domain = normalize_domain(token)
            if domain:
                rules.add(f"DOMAIN-SUFFIX,{domain}")
            continue

        host_match = HOST_LINE_RE.match(line)
        if host_match:
            domain = normalize_domain(host_match.group(1))
            if domain:
                rules.add(f"DOMAIN,{domain}")
            continue

        parsed = parse_domain_or_ip_token(line)
        if parsed:
            rules.add(parsed)
    return rules


def parse_telegram_cidr_text(text: str) -> set[str]:
    return parse_plain_cidr_text(text)


def parse_apnic_country_cidr(text: str, country: str) -> set[str]:
    rules: set[str] = set()
    cc = country.upper()

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 7:
            continue
        _, rec_cc, rec_type, start, value, _, status = parts[:7]
        if rec_cc.upper() != cc:
            continue
        if status not in {"allocated", "assigned"}:
            continue

        if rec_type == "ipv4":
            try:
                count = int(value)
                start_ip = ipaddress.IPv4Address(start)
                end_ip = ipaddress.IPv4Address(int(start_ip) + count - 1)
            except (ValueError, ipaddress.AddressValueError):
                continue
            for net in ipaddress.summarize_address_range(start_ip, end_ip):
                rules.add(format_ip_rule(net))
            continue

        if rec_type == "ipv6":
            try:
                prefix_len = int(value)
                net = ipaddress.IPv6Network(f"{start}/{prefix_len}", strict=False)
            except ValueError:
                continue
            rules.add(format_ip_rule(net))

    return rules


def parse_iana_special_csv(text: str) -> set[str]:
    rules: set[str] = set()
    reader = csv.DictReader(text.splitlines())
    if not reader.fieldnames:
        return rules

    address_key = next((f for f in reader.fieldnames if "Address Block" in f), None)
    reachable_key = next((f for f in reader.fieldnames if "Globally Reachable" in f), None)
    if not address_key:
        return rules

    for row in reader:
        if reachable_key:
            reach_value = (row.get(reachable_key) or "").strip()
            if "false" not in reach_value.lower():
                continue

        block_text = (row.get(address_key) or "").strip()
        if not block_text:
            continue

        block_candidates = [b.strip() for b in block_text.split(",") if b.strip()]
        for block in block_candidates:
            block = FOOTNOTE_RE.sub("", block).strip()
            if not block:
                continue
            try:
                network = ipaddress.ip_network(block, strict=False)
            except ValueError:
                continue
            rules.add(format_ip_rule(network))
    return rules


def parse_aws_ip_ranges(data: bytes, services: list[str]) -> set[str]:
    rules: set[str] = set()
    payload = json.loads(data.decode("utf-8"))
    service_set = {s.upper() for s in services}

    for item in payload.get("prefixes", []):
        service = str(item.get("service", "")).upper()
        if service_set and service not in service_set:
            continue
        prefix = item.get("ip_prefix")
        if not prefix:
            continue
        try:
            rules.add(format_ip_rule(ipaddress.ip_network(prefix, strict=False)))
        except ValueError:
            continue

    for item in payload.get("ipv6_prefixes", []):
        service = str(item.get("service", "")).upper()
        if service_set and service not in service_set:
            continue
        prefix = item.get("ipv6_prefix")
        if not prefix:
            continue
        try:
            rules.add(format_ip_rule(ipaddress.ip_network(prefix, strict=False)))
        except ValueError:
            continue

    return rules


def parse_gcp_ip_ranges(data: bytes) -> set[str]:
    rules: set[str] = set()
    payload = json.loads(data.decode("utf-8"))
    for item in payload.get("prefixes", []):
        for key in ("ipv4Prefix", "ipv6Prefix"):
            prefix = item.get(key)
            if not prefix:
                continue
            try:
                rules.add(format_ip_rule(ipaddress.ip_network(prefix, strict=False)))
            except ValueError:
                continue
    return rules


def parse_iana_tld_list_text(text: str, exclude_tlds: set[str]) -> set[str]:
    rules: set[str] = set()
    excluded = {item.lower() for item in exclude_tlds}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split("#", 1)[0].strip().lower()
        if not token:
            continue
        if token in excluded:
            continue
        # IANA list uses ASCII TLD labels (including punycode where needed).
        if not re.fullmatch(r"[a-z0-9-]{2,63}", token):
            continue
        rules.add(f"DOMAIN-SUFFIX,{token}")
    return rules


def parse_v2fly_attrs(payload: str) -> tuple[str, set[str]]:
    parts = payload.strip().split()
    if not parts:
        return "", set()
    value = parts[0].strip()
    attrs = {part.strip() for part in parts[1:] if part.strip().startswith("@")}
    return value, attrs


def parse_v2fly_dlc_text(
    text: str,
    *,
    include_attrs: set[str],
    exclude_attrs: set[str],
    include_handler: Any,
) -> set[str]:
    rules: set[str] = set()

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if not line:
            continue

        line_type = ""
        payload = line
        if ":" in line:
            prefix, rest = line.split(":", 1)
            prefix = prefix.strip().lower()
            if prefix in {"include", "full", "domain", "keyword", "regexp"}:
                line_type = prefix
                payload = rest.strip()

        if line_type == "include":
            include_name, _ = parse_v2fly_attrs(payload)
            if include_name:
                rules.update(include_handler(include_name))
            continue

        value, attrs = parse_v2fly_attrs(payload)
        if not value:
            continue

        if include_attrs and not (attrs & include_attrs):
            continue
        if exclude_attrs and (attrs & exclude_attrs):
            continue

        if line_type == "full":
            domain = normalize_domain(value)
            if domain:
                rules.add(f"DOMAIN,{domain}")
            continue

        if line_type == "domain":
            domain = normalize_domain(value)
            if domain:
                rules.add(f"DOMAIN-SUFFIX,{domain}")
            continue

        if line_type == "keyword":
            rules.add(f"DOMAIN-KEYWORD,{value}")
            continue

        if line_type == "regexp":
            rules.add(f"DOMAIN-REGEX,{value}")
            continue

        parsed = parse_domain_or_ip_token(value)
        if parsed:
            rules.add(parsed)

    return rules


def parse_v2fly_dlc_source(
    source_urls: list[str],
    cache_dir: pathlib.Path,
    offline: bool,
    include_attrs: set[str],
    exclude_attrs: set[str],
    exclude_includes: set[str],
) -> tuple[set[str], bool, str]:
    if not source_urls:
        raise BuildError("v2fly_dlc source requires at least one URL")

    visited: set[str] = set()
    rules: set[str] = set()
    used_cache_only = True
    base_urls = [candidate.rsplit("/", 1)[0] for candidate in source_urls]
    root_name = source_urls[0].rsplit("/", 1)[-1]
    resolved_root_url = source_urls[0]

    def fetch_relative(name: str) -> tuple[bytes, bool, str]:
        candidates = [f"{base}/{name}" for base in base_urls]
        source = {"url": candidates[0], "fallback_urls": candidates[1:]}
        return fetch_source_bytes(source, cache_dir, offline)

    def walk(name: str) -> set[str]:
        nonlocal used_cache_only
        nonlocal resolved_root_url
        if name in visited:
            return set()
        visited.add(name)

        data, used_cache, chosen_url = fetch_relative(name)
        if name == root_name:
            resolved_root_url = chosen_url
        used_cache_only = used_cache_only and used_cache
        text = decode_text(data)

        def include_handler(include_name: str) -> set[str]:
            if include_name in exclude_includes:
                return set()
            return walk(include_name)

        return parse_v2fly_dlc_text(
            text,
            include_attrs=include_attrs,
            exclude_attrs=exclude_attrs,
            include_handler=include_handler,
        )

    rules.update(walk(root_name))
    return rules, used_cache_only, resolved_root_url


def fetch_bytes(url: str, cache_dir: pathlib.Path, offline: bool = False) -> tuple[bytes, bool]:
    memo_hit = FETCH_MEMO.get(url)
    if memo_hit is not None:
        return memo_hit

    cache_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]
    cache_file = cache_dir / f"{digest}.bin"
    meta_file = cache_dir / f"{digest}.json"

    if offline:
        if not cache_file.exists():
            raise BuildError(f"offline mode: no cache for {url}")
        result = (cache_file.read_bytes(), True)
        record_fetch_event(url, "offline_cache")
        FETCH_MEMO[url] = result
        return result

    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            data = response.read()
        if not data:
            raise BuildError(f"empty response from {url}")
        cache_file.write_bytes(data)
        meta_file.write_text(
            json.dumps({"url": url, "fetched_at_utc": dt.datetime.now(dt.timezone.utc).isoformat()}),
            encoding="utf-8",
        )
        result = (data, False)
        record_fetch_event(url, "network")
        FETCH_MEMO[url] = result
        return result
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        if cache_file.exists():
            log(f"warning: fetch failed for {url}; using cache ({exc})")
            result = (cache_file.read_bytes(), True)
            record_fetch_event(url, "fallback_cache", error=str(exc))
            FETCH_MEMO[url] = result
            return result
        raise BuildError(f"fetch failed for {url}: {exc}") from exc


def collect_source_urls(source: dict[str, Any]) -> list[str]:
    urls: list[str] = []

    primary_url = str(source.get("url", "")).strip()
    if primary_url:
        urls.append(primary_url)

    raw_urls = source.get("urls")
    if raw_urls is not None:
        if not isinstance(raw_urls, list):
            raise BuildError("source field 'urls' must be an array")
        for item in raw_urls:
            candidate = str(item).strip()
            if candidate:
                urls.append(candidate)

    fallback_urls = source.get("fallback_urls")
    if fallback_urls is not None:
        if not isinstance(fallback_urls, list):
            raise BuildError("source field 'fallback_urls' must be an array")
        for item in fallback_urls:
            candidate = str(item).strip()
            if candidate:
                urls.append(candidate)

    deduped: list[str] = []
    seen: set[str] = set()
    for candidate in urls:
        if candidate in seen:
            continue
        seen.add(candidate)
        deduped.append(candidate)
    return deduped


def fetch_source_bytes(source: dict[str, Any], cache_dir: pathlib.Path, offline: bool) -> tuple[bytes, bool, str]:
    candidates = collect_source_urls(source)
    if not candidates:
        raise BuildError("source requires at least one URL (url / urls / fallback_urls)")

    errors: list[str] = []
    for idx, candidate in enumerate(candidates):
        try:
            data, used_cache = fetch_bytes(candidate, cache_dir, offline=offline)
            if idx > 0:
                log(f"using fallback source URL: {candidate}")
            return data, used_cache, candidate
        except BuildError as exc:
            errors.append(f"{candidate}: {exc}")

    raise BuildError("all source URLs failed; " + " | ".join(errors))


def decode_text(data: bytes) -> str:
    return data.decode("utf-8-sig", errors="ignore")


def load_source(
    source: dict[str, Any],
    root_dir: pathlib.Path,
    cache_dir: pathlib.Path,
    offline: bool,
) -> SourceBuildResult:
    source_type = str(source.get("type", "")).strip()
    if not source_type:
        raise BuildError("source missing 'type'")

    if source_type == "local_domain":
        source_path = pathlib.Path(str(source["path"]))
        path = root_dir / source_path
        if not path.exists():
            raise BuildError(f"local file not found: {path}")
        text = path.read_text(encoding="utf-8")
        return SourceBuildResult(parse_local_domain_text(text), False, source_path.as_posix())

    data, used_cache, source_ref = fetch_source_bytes(source, cache_dir, offline)
    text = decode_text(data)

    if source_type == "adblock":
        return SourceBuildResult(parse_adblock_text(text), used_cache, source_ref)
    if source_type == "plain_cidr":
        return SourceBuildResult(parse_plain_cidr_text(text), used_cache, source_ref)
    if source_type == "csv_cidr_first_column":
        return SourceBuildResult(parse_cidr_csv_first_column(text), used_cache, source_ref)
    if source_type == "telegram_cidr":
        return SourceBuildResult(parse_telegram_cidr_text(text), used_cache, source_ref)
    if source_type == "apnic_country_cidr":
        country = str(source.get("country", "")).strip()
        if not country:
            raise BuildError(f"source type {source_type} requires 'country'")
        return SourceBuildResult(parse_apnic_country_cidr(text, country), used_cache, source_ref)
    if source_type == "iana_special_csv":
        return SourceBuildResult(parse_iana_special_csv(text), used_cache, source_ref)
    if source_type == "aws_ip_ranges":
        services = [str(item) for item in source.get("services", [])]
        return SourceBuildResult(parse_aws_ip_ranges(data, services), used_cache, source_ref)
    if source_type == "gcp_ip_ranges":
        return SourceBuildResult(parse_gcp_ip_ranges(data), used_cache, source_ref)
    if source_type == "iana_tld_list":
        exclude_tlds = {str(item).strip().lower() for item in source.get("exclude_tlds", []) if str(item).strip()}
        return SourceBuildResult(parse_iana_tld_list_text(text, exclude_tlds), used_cache, source_ref)
    if source_type == "v2fly_dlc":
        include_attrs = {str(item).strip() for item in source.get("include_attrs", []) if str(item).strip()}
        exclude_attrs = {str(item).strip() for item in source.get("exclude_attrs", []) if str(item).strip()}
        exclude_includes = {
            str(item).strip() for item in source.get("exclude_includes", []) if str(item).strip()
        }
        rules, used_cache_only, resolved_source_ref = parse_v2fly_dlc_source(
            collect_source_urls(source),
            cache_dir=cache_dir,
            offline=offline,
            include_attrs=include_attrs,
            exclude_attrs=exclude_attrs,
            exclude_includes=exclude_includes,
        )
        return SourceBuildResult(rules, used_cache_only, resolved_source_ref)

    raise BuildError(f"unsupported source type: {source_type}")


def write_surge_rules(path: pathlib.Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(rules)
    if body:
        body += "\n"
    path.write_text(body, encoding="utf-8")


def write_openclash_rules(path: pathlib.Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rules:
        path.write_text("payload: []\n", encoding="utf-8")
        return

    lines = ["payload:"]
    for rule in rules:
        escaped = rule.replace("'", "''")
        lines.append(f"  - '{escaped}'")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def split_rules(rules: list[str]) -> tuple[list[str], list[str], list[str], list[str], list[str]]:
    non_ip_rules: list[str] = []
    ip_rules: list[str] = []
    domain_rules: list[str] = []
    ipcidr_payloads: list[str] = []
    surge_domainset_lines: list[str] = []

    for rule in rules:
        if rule.startswith(("IP-CIDR,", "IP-CIDR6,")):
            ip_rules.append(rule)
            parts = rule.split(",", 2)
            if len(parts) >= 2:
                ipcidr_payloads.append(parts[1])
            continue

        non_ip_rules.append(rule)

        if rule.startswith("DOMAIN,"):
            domain = rule.split(",", 1)[1]
            domain_rules.append(domain)
            surge_domainset_lines.append(domain)
            continue

        if rule.startswith("DOMAIN-SUFFIX,"):
            domain = rule.split(",", 1)[1]
            domain_rules.append(f"+.{domain}")
            surge_domainset_lines.append(f".{domain}")

    return non_ip_rules, ip_rules, domain_rules, ipcidr_payloads, surge_domainset_lines


def write_plain_lines(path: pathlib.Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(lines)
    if content:
        content += "\n"
    path.write_text(content, encoding="utf-8")


def read_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def format_repo_path(path: pathlib.Path | None) -> str | None:
    if path is None:
        return None
    try:
        return path.relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return str(path)


def load_policy_map(policy_path: pathlib.Path | None) -> dict[str, dict[str, Any]]:
    if policy_path is None:
        return {}
    if not policy_path.exists():
        return {}
    payload = read_json(policy_path)
    categories = payload.get("categories", {})
    if not isinstance(categories, dict):
        raise BuildError("policy map: 'categories' must be an object")
    out: dict[str, dict[str, Any]] = {}
    for key, value in categories.items():
        if not isinstance(value, dict):
            raise BuildError(f"policy map: category '{key}' must be an object")
        out[str(key)] = value
    return out


def load_ignored_conflict_sets(config: dict[str, Any]) -> set[frozenset[str]]:
    # Keep defaults for compatibility even if config omits this section.
    ignored: set[frozenset[str]] = {frozenset({"domestic", "cncidr"})}
    raw = config.get("ignore_conflicts", [])
    if raw is None:
        return ignored
    if not isinstance(raw, list):
        raise BuildError("config: 'ignore_conflicts' must be a list of category arrays")

    for idx, item in enumerate(raw):
        if not isinstance(item, list):
            raise BuildError(f"config: ignore_conflicts[{idx}] must be an array")
        categories = {str(x).strip() for x in item if str(x).strip()}
        if len(categories) < 2:
            continue
        ignored.add(frozenset(categories))
    return ignored


def load_ignored_rule_conflicts(config: dict[str, Any]) -> dict[str, set[frozenset[str]]]:
    raw = config.get("ignore_conflicts_by_rule", [])
    if raw is None:
        return {}
    if not isinstance(raw, list):
        raise BuildError("config: 'ignore_conflicts_by_rule' must be a list")

    ignored: dict[str, set[frozenset[str]]] = defaultdict(set)
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            raise BuildError(f"config: ignore_conflicts_by_rule[{idx}] must be an object")

        rule = str(item.get("rule", "")).strip()
        if not rule:
            raise BuildError(f"config: ignore_conflicts_by_rule[{idx}] missing 'rule'")

        categories_raw = item.get("categories", [])
        if not isinstance(categories_raw, list):
            raise BuildError(f"config: ignore_conflicts_by_rule[{idx}].categories must be an array")
        categories = {str(x).strip() for x in categories_raw if str(x).strip()}
        if len(categories) < 2:
            continue

        ignored[rule].add(frozenset(categories))
    return ignored


def render_policy_reference_markdown(categories: list[dict[str, Any]]) -> str:
    lines = [
        "# Ruleset Policy Reference",
        "",
        "This file defines the recommended action per category.",
        "",
        "| Category | Action | Priority | Rules | Note |",
        "|---|---:|---:|---:|---|",
    ]
    sorted_rows = sorted(
        categories,
        key=lambda c: (int(c.get("recommended_priority", 9999)), str(c.get("id", ""))),
    )
    for row in sorted_rows:
        category_id = str(row.get("id", ""))
        action = str(row.get("recommended_action", "UNSPECIFIED"))
        priority = int(row.get("recommended_priority", 9999))
        rules = int(row.get("rule_count", 0))
        note = str(row.get("recommended_note", "")).replace("|", "\\|")
        lines.append(f"| `{category_id}` | `{action}` | {priority} | {rules} | {note} |")
    lines.append("")
    lines.append("Action definitions:")
    lines.append("- `DIRECT`: bypass proxy.")
    lines.append("- `PROXY`: route via proxy policy group.")
    lines.append("- `REJECT`: deny with standard reject.")
    lines.append("- `REJECT-DROP`: silently drop packets.")
    lines.append("- `REJECT-NO-DROP`: explicit reject without drop.")
    lines.append("")
    return "\n".join(lines)


def render_rule_catalog_markdown(categories: list[dict[str, Any]]) -> str:
    lines = [
        "# Ruleset Catalog",
        "",
        "Use with base URL:",
        "`https://raw.githubusercontent.com/<owner>/<repo>/main/ruleset/dist`",
        "",
        "| Category | Action | Priority | Rules | OpenClash (YAML) | Surge | Compat (txt/conf) | Note |",
        "|---|---|---:|---:|---|---|---|---|",
    ]
    sorted_rows = sorted(
        categories,
        key=lambda c: (int(c.get("recommended_priority", 9999)), str(c.get("id", ""))),
    )
    for row in sorted_rows:
        category_id = str(row.get("id", ""))
        action = str(row.get("recommended_action", "UNSPECIFIED"))
        priority = int(row.get("recommended_priority", 9999))
        rules = int(row.get("rule_count", 0))
        note = str(row.get("recommended_note", "")).replace("|", "\\|")

        openclash_paths = "<br>".join(
            [
                f"`openclash/{category_id}.yaml`",
                f"`openclash/non_ip/{category_id}.yaml`",
                f"`openclash/ip/{category_id}.yaml`",
            ]
        )
        surge_paths = "<br>".join(
            [
                f"`surge/{category_id}.list`",
                f"`surge/non_ip/{category_id}.list`",
                f"`surge/ip/{category_id}.list`",
                f"`surge/domainset/{category_id}.conf`",
            ]
        )
        compat_paths = "<br>".join(
            [
                f"`compat/Clash/non_ip/{category_id}.txt`",
                f"`compat/Clash/ip/{category_id}.txt`",
                f"`compat/Clash/domainset/{category_id}.txt`",
                f"`compat/List/non_ip/{category_id}.conf`",
                f"`compat/List/ip/{category_id}.conf`",
                f"`compat/List/domainset/{category_id}.conf`",
            ]
        )
        lines.append(
            f"| `{category_id}` | `{action}` | {priority} | {rules} | {openclash_paths} | {surge_paths} | {compat_paths} | {note} |"
        )

    lines.append("")
    lines.append("Action definitions:")
    lines.append("- `DIRECT`: bypass proxy.")
    lines.append("- `PROXY`: route via proxy policy group.")
    lines.append("- `REJECT`: deny with standard reject.")
    lines.append("- `REJECT-DROP`: silently drop packets.")
    lines.append("- `REJECT-NO-DROP`: explicit reject without drop.")
    lines.append("")
    return "\n".join(lines)


def build_category(
    category: dict[str, Any],
    root_dir: pathlib.Path,
    cache_dir: pathlib.Path,
    offline: bool,
) -> tuple[list[str], list[dict[str, Any]]]:
    category_id = str(category.get("id", "")).strip()
    if not category_id:
        raise BuildError("category missing 'id'")

    sources = category.get("sources", [])
    if not isinstance(sources, list) or not sources:
        raise BuildError(f"category {category_id} has no sources")

    rules: set[str] = set()
    source_meta: list[dict[str, Any]] = []

    for source in sources:
        result = load_source(source, root_dir, cache_dir, offline)
        rules.update(result.rules)
        source_meta.append(
            {
                "type": source["type"],
                "authority": source.get("authority", "unspecified"),
                "ref": result.source_ref,
                "used_cache": result.used_cache,
                "rule_count": len(result.rules),
            }
        )

    exclude_path = category.get("exclude_rules_path")
    if exclude_path:
        exclusion_file = root_dir / str(exclude_path)
        if exclusion_file.exists():
            exclude_rules = parse_local_domain_text(exclusion_file.read_text(encoding="utf-8"))
            before_count = len(rules)
            rules.difference_update(exclude_rules)
            removed = before_count - len(rules)
            if removed > 0:
                log(f"{category_id}: removed {removed} rules from exclusion file")

    allow_path = category.get("allow_rules_path")
    if allow_path:
        allow_file = root_dir / str(allow_path)
        if allow_file.exists():
            allow_rules = parse_local_domain_text(allow_file.read_text(encoding="utf-8"))
            before_count = len(rules)
            rules.difference_update(allow_rules)
            removed = before_count - len(rules)
            if removed > 0:
                log(f"{category_id}: removed {removed} rules from allowlist file")

    sorted_rules = sorted(rules, key=rule_sort_key)
    return sorted_rules, source_meta


def build_all(
    config_path: pathlib.Path,
    policy_path: pathlib.Path | None,
    dist_dir: pathlib.Path,
    cache_dir: pathlib.Path,
    offline: bool,
    fail_on_conflicts: bool,
    fail_on_cross_action_conflicts: bool,
) -> int:
    FETCH_MEMO.clear()
    FETCH_EVENTS.clear()
    config = read_json(config_path)
    policy_map = load_policy_map(policy_path)
    ignored_conflict_sets = load_ignored_conflict_sets(config)
    ignored_rule_conflicts = load_ignored_rule_conflicts(config)
    categories = config.get("categories", [])
    if not isinstance(categories, list) or not categories:
        raise BuildError("config has no categories")

    dist_dir.mkdir(parents=True, exist_ok=True)
    removed_duplicates = purge_duplicate_artifacts(dist_dir)
    if removed_duplicates > 0:
        log(f"removed {removed_duplicates} duplicate artifacts from dist directory")
    for stale in (dist_dir / "surge", dist_dir / "openclash", dist_dir / "compat", dist_dir / "meta"):
        if stale.exists():
            shutil.rmtree(stale)
    for stale_file in (
        dist_dir / "index.json",
        dist_dir / "conflicts.json",
        dist_dir / "fetch_report.json",
        dist_dir / "policy_reference.json",
        dist_dir / "policy_reference.md",
        dist_dir / "rule_catalog.md",
    ):
        if stale_file.exists():
            stale_file.unlink()

    surge_dir = dist_dir / "surge"
    openclash_dir = dist_dir / "openclash"

    rules_by_category: dict[str, list[str]] = {}
    category_actions: dict[str, str] = {}
    metadata_categories: list[dict[str, Any]] = []
    missing_policy: list[str] = []

    for category in categories:
        category_id = str(category.get("id", "")).strip()
        if not category_id:
            raise BuildError("category missing id")
        log(f"building category: {category_id}")

        rules, source_meta = build_category(category, ROOT_DIR, cache_dir, offline)
        rules_by_category[category_id] = rules

        policy_entry = policy_map.get(category_id, {})
        action = str(policy_entry.get("action", "UNSPECIFIED")).upper().strip()
        if action not in ALLOWED_ACTIONS:
            raise BuildError(f"policy map: invalid action '{action}' for category '{category_id}'")
        category_actions[category_id] = action
        priority = int(policy_entry.get("priority", 9999))
        note = str(policy_entry.get("note", "")).strip()
        if action == "UNSPECIFIED":
            missing_policy.append(category_id)

        surge_file = surge_dir / f"{category_id}.list"
        openclash_file = openclash_dir / f"{category_id}.yaml"
        write_surge_rules(surge_file, rules)
        write_openclash_rules(openclash_file, rules)

        non_ip_rules, ip_rules, domainset_lines_oc, ipcidr_lines, domainset_lines_surge = split_rules(rules)

        write_surge_rules(dist_dir / "surge" / "non_ip" / f"{category_id}.list", non_ip_rules)
        write_surge_rules(dist_dir / "surge" / "ip" / f"{category_id}.list", ip_rules)
        write_plain_lines(dist_dir / "surge" / "domainset" / f"{category_id}.conf", domainset_lines_surge)

        write_openclash_rules(dist_dir / "openclash" / "non_ip" / f"{category_id}.yaml", non_ip_rules)
        write_openclash_rules(dist_dir / "openclash" / "ip" / f"{category_id}.yaml", ip_rules)
        write_plain_lines(dist_dir / "openclash" / "domainset" / f"{category_id}.txt", domainset_lines_oc)
        write_plain_lines(dist_dir / "openclash" / "ipcidr" / f"{category_id}.txt", ipcidr_lines)

        # Compatibility tree for direct replacement of common public ruleset layouts.
        write_surge_rules(dist_dir / "compat" / "Clash" / "non_ip" / f"{category_id}.txt", non_ip_rules)
        write_surge_rules(dist_dir / "compat" / "Clash" / "ip" / f"{category_id}.txt", ip_rules)
        write_plain_lines(dist_dir / "compat" / "Clash" / "domainset" / f"{category_id}.txt", domainset_lines_oc)
        write_surge_rules(dist_dir / "compat" / "List" / "non_ip" / f"{category_id}.conf", non_ip_rules)
        write_surge_rules(dist_dir / "compat" / "List" / "ip" / f"{category_id}.conf", ip_rules)
        write_plain_lines(dist_dir / "compat" / "List" / "domainset" / f"{category_id}.conf", domainset_lines_surge)

        metadata_categories.append(
            {
                "id": category_id,
                "description": category.get("description", ""),
                "rule_count": len(rules),
                "surge_path": str(surge_file.relative_to(dist_dir)),
                "openclash_path": str(openclash_file.relative_to(dist_dir)),
                "surge_non_ip_path": str((dist_dir / "surge" / "non_ip" / f"{category_id}.list").relative_to(dist_dir)),
                "surge_ip_path": str((dist_dir / "surge" / "ip" / f"{category_id}.list").relative_to(dist_dir)),
                "surge_domainset_path": str((dist_dir / "surge" / "domainset" / f"{category_id}.conf").relative_to(dist_dir)),
                "openclash_non_ip_path": str((dist_dir / "openclash" / "non_ip" / f"{category_id}.yaml").relative_to(dist_dir)),
                "openclash_ip_path": str((dist_dir / "openclash" / "ip" / f"{category_id}.yaml").relative_to(dist_dir)),
                "openclash_domainset_path": str((dist_dir / "openclash" / "domainset" / f"{category_id}.txt").relative_to(dist_dir)),
                "openclash_ipcidr_path": str((dist_dir / "openclash" / "ipcidr" / f"{category_id}.txt").relative_to(dist_dir)),
                "compat_clash_non_ip_path": str((dist_dir / "compat" / "Clash" / "non_ip" / f"{category_id}.txt").relative_to(dist_dir)),
                "compat_clash_ip_path": str((dist_dir / "compat" / "Clash" / "ip" / f"{category_id}.txt").relative_to(dist_dir)),
                "compat_clash_domainset_path": str((dist_dir / "compat" / "Clash" / "domainset" / f"{category_id}.txt").relative_to(dist_dir)),
                "compat_list_non_ip_path": str((dist_dir / "compat" / "List" / "non_ip" / f"{category_id}.conf").relative_to(dist_dir)),
                "compat_list_ip_path": str((dist_dir / "compat" / "List" / "ip" / f"{category_id}.conf").relative_to(dist_dir)),
                "compat_list_domainset_path": str((dist_dir / "compat" / "List" / "domainset" / f"{category_id}.conf").relative_to(dist_dir)),
                "recommended_action": action,
                "recommended_priority": priority,
                "recommended_note": note,
                "sources": source_meta,
            }
        )

        # Per-category sidecar metadata for auditing and ops.
        sidecar_dir = dist_dir / "meta"
        sidecar_dir.mkdir(parents=True, exist_ok=True)
        sidecar_path = sidecar_dir / f"{category_id}.json"
        sidecar_path.write_text(
            json.dumps(
                {
                    "id": category_id,
                    "description": category.get("description", ""),
                    "recommended_action": action,
                    "recommended_priority": priority,
                    "recommended_note": note,
                    "rule_count": len(rules),
                    "paths": {
                        "surge": str(surge_file.relative_to(dist_dir)),
                        "surge_non_ip": str((dist_dir / "surge" / "non_ip" / f"{category_id}.list").relative_to(dist_dir)),
                        "surge_ip": str((dist_dir / "surge" / "ip" / f"{category_id}.list").relative_to(dist_dir)),
                        "surge_domainset": str((dist_dir / "surge" / "domainset" / f"{category_id}.conf").relative_to(dist_dir)),
                        "openclash": str(openclash_file.relative_to(dist_dir)),
                        "openclash_non_ip": str((dist_dir / "openclash" / "non_ip" / f"{category_id}.yaml").relative_to(dist_dir)),
                        "openclash_ip": str((dist_dir / "openclash" / "ip" / f"{category_id}.yaml").relative_to(dist_dir)),
                        "openclash_domainset": str((dist_dir / "openclash" / "domainset" / f"{category_id}.txt").relative_to(dist_dir)),
                        "openclash_ipcidr": str((dist_dir / "openclash" / "ipcidr" / f"{category_id}.txt").relative_to(dist_dir)),
                        "compat_clash_non_ip": str((dist_dir / "compat" / "Clash" / "non_ip" / f"{category_id}.txt").relative_to(dist_dir)),
                        "compat_clash_ip": str((dist_dir / "compat" / "Clash" / "ip" / f"{category_id}.txt").relative_to(dist_dir)),
                        "compat_clash_domainset": str((dist_dir / "compat" / "Clash" / "domainset" / f"{category_id}.txt").relative_to(dist_dir)),
                        "compat_list_non_ip": str((dist_dir / "compat" / "List" / "non_ip" / f"{category_id}.conf").relative_to(dist_dir)),
                        "compat_list_ip": str((dist_dir / "compat" / "List" / "ip" / f"{category_id}.conf").relative_to(dist_dir)),
                        "compat_list_domainset": str((dist_dir / "compat" / "List" / "domainset" / f"{category_id}.conf").relative_to(dist_dir))
                    },
                    "sources": source_meta
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    rule_index: dict[str, list[str]] = defaultdict(list)
    for category_id, rules in rules_by_category.items():
        for rule in rules:
            rule_index[rule].append(category_id)

    reject_like = {"reject", "reject_extra", "reject_drop", "reject_no_drop"}
    overlay_categories = {"gfw", "global", "tld_proxy"}

    conflicts: list[dict[str, Any]] = []
    for rule, category_ids in rule_index.items():
        category_set = set(category_ids)
        if len(category_set) <= 1:
            continue

        # "direct" is an aggregate convenience set. If this rule is also present in
        # other explicit DIRECT categories, evaluate conflicts on concrete categories first.
        if "direct" in category_set:
            has_explicit_direct = any(
                cid != "direct" and category_actions.get(cid, "UNSPECIFIED") == "DIRECT" for cid in category_set
            )
            if has_explicit_direct:
                category_set.discard("direct")

        if len(category_set) <= 1:
            continue

        frozen_set = frozenset(category_set)
        if frozen_set in ignored_conflict_sets:
            continue

        by_rule = ignored_rule_conflicts.get(rule, set())
        if frozen_set in by_rule:
            continue

        actions = {category_id: category_actions.get(category_id, "UNSPECIFIED") for category_id in category_set}
        families = {action_family(v) for v in actions.values()}

        # reject/reject_extra/reject_drop/reject_no_drop are intentionally split layers.
        if category_set.issubset(reject_like):
            continue

        # Reject-family overlap with other categories is expected in ad/tracker feeds.
        if category_set & reject_like:
            continue

        # direct is an aggregate of direct-like categories; same-action overlap is expected.
        if "direct" in category_set:
            non_direct_actions = {action for cid, action in actions.items() if cid != "direct"}
            if non_direct_actions and all(action == "DIRECT" for action in non_direct_actions):
                continue

        # global/gfw/tld_proxy are overlay sets and intentionally overlap.
        if category_set & overlay_categories:
            continue

        if len(families) <= 1:
            conflict_type = "same_action_overlap"
            severity = "low"
        elif "DIRECT" in families and "PROXY" in families:
            conflict_type = "direct_proxy_conflict"
            severity = "high"
        elif "DIRECT" in families and "REJECT" in families:
            conflict_type = "direct_reject_conflict"
            severity = "high"
        elif "PROXY" in families and "REJECT" in families:
            conflict_type = "proxy_reject_conflict"
            severity = "medium"
        else:
            conflict_type = "cross_action_conflict"
            severity = "medium"

        conflicts.append(
            {
                "rule": rule,
                "categories": sorted(category_set),
                "actions": [
                    {
                        "category": cid,
                        "action": actions[cid],
                        "action_family": action_family(actions[cid]),
                    }
                    for cid in sorted(category_set)
                ],
                "type": conflict_type,
                "severity": severity,
            }
        )

    severity_weight = {"high": 0, "medium": 1, "low": 2}
    conflicts.sort(
        key=lambda item: (
            severity_weight.get(str(item.get("severity", "low")), 3),
            len(item["categories"]) * -1,
            item["rule"],
        )
    )
    cross_action_conflict_count = sum(1 for item in conflicts if item["type"] != "same_action_overlap")
    high_severity_conflict_count = sum(1 for item in conflicts if item["severity"] == "high")
    medium_severity_conflict_count = sum(1 for item in conflicts if item["severity"] == "medium")
    low_severity_conflict_count = sum(1 for item in conflicts if item["severity"] == "low")

    conflicts_file = dist_dir / "conflicts.json"
    conflicts_file.write_text(
        json.dumps(
            {
                "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "conflict_count": len(conflicts),
                "cross_action_conflict_count": cross_action_conflict_count,
                "high_severity_conflict_count": high_severity_conflict_count,
                "medium_severity_conflict_count": medium_severity_conflict_count,
                "low_severity_conflict_count": low_severity_conflict_count,
                "conflicts": conflicts,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    fetch_report_file = dist_dir / "fetch_report.json"
    fetch_report = build_fetch_report()
    fetch_report_file.write_text(
        json.dumps(fetch_report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    manifest = {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "config_path": format_repo_path(config_path),
        "policy_path": format_repo_path(policy_path),
        "category_count": len(metadata_categories),
        "conflict_count": len(conflicts),
        "cross_action_conflict_count": cross_action_conflict_count,
        "high_severity_conflict_count": high_severity_conflict_count,
        "fetch_report_path": str(fetch_report_file.relative_to(dist_dir)),
        "categories": metadata_categories,
    }
    manifest_file = dist_dir / "index.json"
    manifest_file.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    policy_reference_json = dist_dir / "policy_reference.json"
    policy_reference_json.write_text(
        json.dumps(
            {
                "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "policy_path": format_repo_path(policy_path),
                "categories": [
                    {
                        "id": c["id"],
                        "recommended_action": c["recommended_action"],
                        "recommended_priority": c["recommended_priority"],
                        "recommended_note": c["recommended_note"],
                        "rule_count": c["rule_count"],
                    }
                    for c in metadata_categories
                ],
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


    log(f"build completed: {len(metadata_categories)} categories")
    log(
        "conflicts detected: "
        f"total={len(conflicts)} cross_action={cross_action_conflict_count} high={high_severity_conflict_count}"
    )
    log(
        "fetch summary: "
        f"network={fetch_report['network_success_count']} "
        f"offline_cache={fetch_report['offline_cache_count']} "
        f"fallback_cache={fetch_report['fallback_cache_count']}"
    )
    if missing_policy:
        log(f"warning: missing policy map for categories: {', '.join(sorted(missing_policy))}")

    if fail_on_conflicts and conflicts:
        return 2
    if fail_on_cross_action_conflicts and cross_action_conflict_count > 0:
        return 3
    return 0


def build_all_staged(
    config_path: pathlib.Path,
    policy_path: pathlib.Path | None,
    dist_dir: pathlib.Path,
    cache_dir: pathlib.Path,
    offline: bool,
    fail_on_conflicts: bool,
    fail_on_cross_action_conflicts: bool,
) -> int:
    """
    Build into a fresh staging directory and atomically replace dist_dir.

    This avoids sync-conflict duplicate artifacts (e.g. '* 2.list') in
    cloud-synced folders by preventing in-place multi-file rewrites.
    """
    dist_parent = dist_dir.parent
    dist_parent.mkdir(parents=True, exist_ok=True)
    staging_dir = pathlib.Path(
        tempfile.mkdtemp(prefix=f".{dist_dir.name}.staging.", dir=str(dist_parent))
    )
    try:
        code = build_all(
            config_path=config_path,
            policy_path=policy_path,
            dist_dir=staging_dir,
            cache_dir=cache_dir,
            offline=offline,
            fail_on_conflicts=fail_on_conflicts,
            fail_on_cross_action_conflicts=fail_on_cross_action_conflicts,
        )

        # A final duplicate sweep in staging prevents sync-generated conflict copies.
        removed_duplicates = purge_duplicate_artifacts(staging_dir)
        if removed_duplicates > 0:
            log(f"staging cleanup removed {removed_duplicates} duplicate artifacts")

        if dist_dir.exists():
            shutil.rmtree(dist_dir)
        staging_dir.replace(dist_dir)
        if not dist_dir.exists():
            renamed_candidates = sorted(
                path for path in dist_parent.glob(f"{dist_dir.name} *") if path.is_dir()
            )
            if len(renamed_candidates) == 1:
                log(
                    f"warning: dist directory was renamed to {renamed_candidates[0].name}; restoring expected path"
                )
                renamed_candidates[0].replace(dist_dir)
        return code
    finally:
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build self-owned rulesets for OpenClash and Surge from authoritative sources."
    )
    parser.add_argument(
        "--config",
        type=pathlib.Path,
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to source config JSON (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--policy",
        type=pathlib.Path,
        default=DEFAULT_POLICY_PATH,
        help=f"Path to policy map JSON (default: {DEFAULT_POLICY_PATH})",
    )
    parser.add_argument(
        "--dist-dir",
        type=pathlib.Path,
        default=DEFAULT_DIST_DIR,
        help=f"Output directory (default: {DEFAULT_DIST_DIR})",
    )
    parser.add_argument(
        "--cache-dir",
        type=pathlib.Path,
        default=DEFAULT_CACHE_DIR,
        help=f"Cache directory for downloaded sources (default: {DEFAULT_CACHE_DIR})",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Disable network fetches and build from local files plus cache only.",
    )
    parser.add_argument(
        "--fail-on-conflicts",
        action="store_true",
        help="Exit non-zero if duplicate rules appear across categories.",
    )
    parser.add_argument(
        "--fail-on-cross-action-conflicts",
        action="store_true",
        help="Exit non-zero only when a rule overlaps across different action families.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return build_all_staged(
            config_path=args.config,
            policy_path=args.policy,
            dist_dir=args.dist_dir,
            cache_dir=args.cache_dir,
            offline=args.offline,
            fail_on_conflicts=args.fail_on_conflicts,
            fail_on_cross_action_conflicts=args.fail_on_cross_action_conflicts,
        )
    except BuildError as exc:
        log(f"error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
