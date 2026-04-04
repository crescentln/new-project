#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any


STREAM_SPLIT_IDS = {"stream_us", "stream_jp", "stream_hk", "stream_tw", "stream_global"}


def load_categories(policy_reference_path: pathlib.Path) -> list[dict[str, Any]]:
    payload = json.loads(policy_reference_path.read_text(encoding="utf-8"))
    categories = payload.get("categories", [])
    if not isinstance(categories, list):
        raise RuntimeError(f"invalid policy reference: {policy_reference_path}")

    rows: list[dict[str, Any]] = []
    for row in categories:
        if not isinstance(row, dict):
            continue
        category_id = str(row.get("id", "")).strip()
        action = str(row.get("recommended_action", "UNSPECIFIED")).upper().strip()
        if not category_id:
            continue
        priority = int(row.get("recommended_priority", 9999))
        rows.append(
            {
                "id": category_id,
                "action": action,
                "priority": priority,
            }
        )

    rows.sort(key=lambda item: (int(item["priority"]), str(item["id"])))

    # If unified stream is available, prefer it in recommended templates and hide
    # the optional split stream categories to keep one-click config concise.
    category_ids = {str(item["id"]) for item in rows}
    if "stream" in category_ids:
        rows = [item for item in rows if str(item["id"]) not in STREAM_SPLIT_IDS]

    return rows


def normalize_policy(action: str, proxy_policy: str) -> str:
    action = str(action).upper().strip()
    if action in {"DIRECT", "REJECT", "REJECT-DROP", "REJECT-NO-DROP"}:
        return action
    if action == "PROXY":
        return proxy_policy
    return proxy_policy


def render_openclash_template(
    categories: list[dict[str, Any]],
    raw_base_url: str,
    interval: int,
    proxy_policy: str,
) -> str:
    lines = [
        "# Generated file: recommended OpenClash template (rule-providers + rules)",
        "# If your proxy policy group name is not PROXY, replace it in rules below.",
        "rule-providers:",
    ]

    for row in categories:
        category_id = str(row["id"])
        lines.extend(
            [
                f"  {category_id}:",
                "    type: http",
                "    behavior: classical",
                f"    path: ./rule_provider/{category_id}.yaml",
                f"    url: {raw_base_url}/openclash/{category_id}.yaml",
                f"    interval: {interval}",
            ]
        )

    lines.append("rules:")
    for row in categories:
        category_id = str(row["id"])
        policy = normalize_policy(str(row["action"]), proxy_policy)
        lines.append(f"  - RULE-SET,{category_id},{policy}")
    lines.append(f"  - MATCH,{proxy_policy}")
    lines.append("")
    return "\n".join(lines)


def render_surge_template(
    categories: list[dict[str, Any]],
    raw_base_url: str,
    interval: int,
    proxy_policy: str,
) -> str:
    lines = [
        "# Generated file: recommended Surge [Rule] snippet",
        "# If your proxy policy group name is not PROXY, replace it in rules below.",
        "[Rule]",
    ]
    for row in categories:
        category_id = str(row["id"])
        policy = normalize_policy(str(row["action"]), proxy_policy)
        lines.append(
            f"RULE-SET,{raw_base_url}/surge/{category_id}.list,{policy},update-interval={interval}"
        )
    lines.append(f"FINAL,{proxy_policy}")
    lines.append("")
    return "\n".join(lines)


def render_stash_template(
    categories: list[dict[str, Any]],
    raw_base_url: str,
    interval: int,
    proxy_policy: str,
) -> str:
    lines = [
        "# Generated file: recommended Stash template (classical rule-providers)",
        "# For Stash-native optimized usage, prefer ruleset/dist/stash/domainset + ipcidr + classical split paths.",
        "rule-providers:",
    ]

    for row in categories:
        category_id = str(row["id"])
        lines.extend(
            [
                f"  {category_id}:",
                "    behavior: classical",
                "    format: text",
                f"    url: {raw_base_url}/stash/{category_id}.list",
                f"    interval: {interval}",
            ]
        )

    lines.append("rules:")
    for row in categories:
        category_id = str(row["id"])
        policy = normalize_policy(str(row["action"]), proxy_policy)
        lines.append(f"  - RULE-SET,{category_id},{policy}")
    lines.append(f"  - MATCH,{proxy_policy}")
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate recommended OpenClash/Surge templates from policy reference.")
    parser.add_argument(
        "--policy-reference",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/policy_reference.json"),
        help="Path to policy_reference.json",
    )
    parser.add_argument(
        "--openclash-out",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/recommended_openclash.yaml"),
        help="Output OpenClash template path",
    )
    parser.add_argument(
        "--surge-out",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/recommended_surge.conf"),
        help="Output Surge template path",
    )
    parser.add_argument(
        "--stash-out",
        type=pathlib.Path,
        default=pathlib.Path("ruleset/dist/recommended_stash.yaml"),
        help="Output Stash template path",
    )
    parser.add_argument(
        "--raw-base-url",
        type=str,
        default="https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist",
        help="Raw base URL for generated template links",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=86400,
        help="Update interval for generated templates",
    )
    parser.add_argument(
        "--proxy-policy",
        type=str,
        default="PROXY",
        help="Proxy policy group name",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    categories = load_categories(args.policy_reference)
    openclash_text = render_openclash_template(
        categories=categories,
        raw_base_url=args.raw_base_url.rstrip("/"),
        interval=args.interval,
        proxy_policy=args.proxy_policy,
    )
    surge_text = render_surge_template(
        categories=categories,
        raw_base_url=args.raw_base_url.rstrip("/"),
        interval=args.interval,
        proxy_policy=args.proxy_policy,
    )
    stash_text = render_stash_template(
        categories=categories,
        raw_base_url=args.raw_base_url.rstrip("/"),
        interval=args.interval,
        proxy_policy=args.proxy_policy,
    )

    args.openclash_out.parent.mkdir(parents=True, exist_ok=True)
    args.surge_out.parent.mkdir(parents=True, exist_ok=True)
    args.stash_out.parent.mkdir(parents=True, exist_ok=True)
    args.openclash_out.write_text(openclash_text, encoding="utf-8")
    args.surge_out.write_text(surge_text, encoding="utf-8")
    args.stash_out.write_text(stash_text, encoding="utf-8")
    print(f"[templates] wrote {args.openclash_out}")
    print(f"[templates] wrote {args.surge_out}")
    print(f"[templates] wrote {args.stash_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
