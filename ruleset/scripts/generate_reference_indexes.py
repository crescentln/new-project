#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
from collections import Counter
from typing import Any


def read_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def escape_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def normalize_base_url(raw_base_url: str) -> str:
    return raw_base_url.rstrip("/")


def source_authority_bucket(authority: str) -> str:
    value = authority.strip().lower()
    if "official" in value:
        return "official"
    if "community" in value or "curated" in value:
        return "community"
    if "owner" in value:
        return "owner"
    return "other"


def parse_categories(index_payload: dict[str, Any]) -> list[dict[str, Any]]:
    categories = index_payload.get("categories")
    if not isinstance(categories, list):
        raise ValueError("index payload missing categories array")
    rows: list[dict[str, Any]] = []
    for row in categories:
        if not isinstance(row, dict):
            continue
        category_id = str(row.get("id", "")).strip()
        if not category_id:
            continue
        rows.append(row)
    rows.sort(key=lambda row: (int(row.get("recommended_priority", 9999)), str(row.get("id", ""))))
    return rows


def render_url_catalog(categories: list[dict[str, Any]], raw_base_url: str) -> str:
    base = normalize_base_url(raw_base_url)
    lines = [
        "# Ruleset URL Catalog",
        "",
        f"Generated at (UTC): `{dt.datetime.now(dt.timezone.utc).isoformat()}`",
        "",
        f"Raw Base: `{base}`",
        "",
        "| Category | Action | Priority | Rules | OpenClash | Surge | Stash | Note |",
        "|---|---|---:|---:|---|---|---|---|",
    ]

    for row in categories:
        category_id = str(row.get("id", ""))
        action = str(row.get("recommended_action", "UNSPECIFIED"))
        priority = int(row.get("recommended_priority", 9999))
        rule_count = int(row.get("rule_count", 0))
        note = escape_cell(str(row.get("recommended_note", "")))
        openclash_path = str(row.get("openclash_path", ""))
        surge_path = str(row.get("surge_path", ""))
        stash_path = str(row.get("stash_path", ""))
        openclash_url = f"{base}/{openclash_path}" if openclash_path else ""
        surge_url = f"{base}/{surge_path}" if surge_path else ""
        stash_url = f"{base}/{stash_path}" if stash_path else ""
        openclash_cell = f"[{openclash_path}]({openclash_url})" if openclash_path else ""
        surge_cell = f"[{surge_path}]({surge_url})" if surge_path else ""
        stash_cell = f"[{stash_path}]({stash_url})" if stash_path else ""
        lines.append(
            f"| `{category_id}` | `{action}` | {priority} | {rule_count} | {openclash_cell} | {surge_cell} | {stash_cell} | {note} |"
        )

    lines.append("")
    lines.append("说明：上表是每个分类的“单 URL 主入口”（OpenClash YAML + Surge list）。")
    lines.append("")
    return "\n".join(lines)


def render_source_authority(categories: list[dict[str, Any]]) -> str:
    authority_totals: Counter[str] = Counter()
    type_totals: Counter[str] = Counter()
    for row in categories:
        sources = row.get("sources", [])
        if not isinstance(sources, list):
            continue
        for source in sources:
            if not isinstance(source, dict):
                continue
            authority = source_authority_bucket(str(source.get("authority", "unspecified")))
            source_type = str(source.get("type", "unknown")).strip() or "unknown"
            authority_totals[authority] += 1
            type_totals[source_type] += 1

    lines = [
        "# Source Authority Matrix",
        "",
        f"Generated at (UTC): `{dt.datetime.now(dt.timezone.utc).isoformat()}`",
        "",
        "## Overall",
        "",
        "| Authority | Source Entries |",
        "|---|---:|",
    ]

    for bucket in ("official", "community", "owner", "other"):
        lines.append(f"| `{bucket}` | {authority_totals.get(bucket, 0)} |")

    lines.append("")
    lines.append("| Source Type | Source Entries |")
    lines.append("|---|---:|")
    for source_type, count in sorted(type_totals.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"| `{escape_cell(source_type)}` | {count} |")

    lines.extend(
        [
            "",
            "## Category Matrix",
            "",
            "| Category | Action | Rules | Official | Community | Owner | Other | Sources |",
            "|---|---|---:|---:|---:|---:|---:|---|",
        ]
    )

    for row in categories:
        category_id = str(row.get("id", ""))
        action = str(row.get("recommended_action", "UNSPECIFIED"))
        rule_count = int(row.get("rule_count", 0))
        counts = Counter()
        source_refs: list[str] = []
        sources = row.get("sources", [])
        if isinstance(sources, list):
            for source in sources:
                if not isinstance(source, dict):
                    continue
                authority_raw = str(source.get("authority", "unspecified"))
                bucket = source_authority_bucket(authority_raw)
                counts[bucket] += 1
                source_type = str(source.get("type", "unknown")).strip() or "unknown"
                source_ref = str(source.get("ref", "")).strip()
                source_refs.append(f"`{authority_raw}` `{source_type}` `{escape_cell(source_ref)}`")

        refs_cell = "<br>".join(source_refs) if source_refs else ""
        lines.append(
            f"| `{category_id}` | `{action}` | {rule_count} | {counts.get('official', 0)} | "
            f"{counts.get('community', 0)} | {counts.get('owner', 0)} | {counts.get('other', 0)} | {refs_cell} |"
        )

    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate URL catalog and source authority reports.")
    parser.add_argument("--index", type=pathlib.Path, required=True, help="Path to dist/index.json")
    parser.add_argument("--raw-base-url", type=str, required=True, help="Raw base URL for ruleset dist")
    parser.add_argument("--urls-out", type=pathlib.Path, required=True, help="Output markdown for URL catalog")
    parser.add_argument(
        "--sources-out", type=pathlib.Path, required=True, help="Output markdown for source authority matrix"
    )
    args = parser.parse_args()

    index_payload = read_json(args.index)
    categories = parse_categories(index_payload)

    args.urls_out.parent.mkdir(parents=True, exist_ok=True)
    args.sources_out.parent.mkdir(parents=True, exist_ok=True)
    args.urls_out.write_text(render_url_catalog(categories, args.raw_base_url), encoding="utf-8")
    args.sources_out.write_text(render_source_authority(categories), encoding="utf-8")

    print(
        "[reference] generated "
        f"categories={len(categories)} urls={args.urls_out} sources={args.sources_out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
