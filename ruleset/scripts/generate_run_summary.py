#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any


def read_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_counts(payload: dict[str, Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in payload.get("categories", []):
        if not isinstance(row, dict):
            continue
        category_id = str(row.get("id", "")).strip()
        if not category_id:
            continue
        try:
            out[category_id] = int(row.get("rule_count", 0))
        except (TypeError, ValueError):
            continue
    return out


def parse_thresholds(payload: dict[str, Any]) -> tuple[dict[str, int], dict[str, int]]:
    minimums = payload.get("minimum_rule_counts", {})
    warnings = payload.get("warning_rule_counts", {})
    if not isinstance(minimums, dict):
        minimums = {}
    if not isinstance(warnings, dict):
        warnings = {}
    return (
        {str(k): int(v) for k, v in minimums.items()},
        {str(k): int(v) for k, v in warnings.items()},
    )


def build_watchlist(
    counts: dict[str, int],
    minimums: dict[str, int],
    warnings: dict[str, int],
    limit: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for category_id, minimum in minimums.items():
        current = counts.get(category_id, 0)
        warning = warnings.get(category_id)
        ratio = float("inf") if minimum <= 0 else current / minimum
        near_warning = warning is not None and current <= warning
        rows.append(
            {
                "id": category_id,
                "current": current,
                "minimum": minimum,
                "warning": warning,
                "headroom": current - minimum,
                "ratio": ratio,
                "near_warning": near_warning,
            }
        )

    rows.sort(
        key=lambda item: (
            0 if item["near_warning"] else 1,
            item["ratio"],
            item["headroom"],
            item["id"],
        )
    )
    return rows[: max(limit, 1)]


def diff_counts(before: dict[str, int], after: dict[str, int], limit: int) -> list[tuple[str, int, int, int]]:
    changes: list[tuple[str, int, int, int]] = []
    for category_id in sorted(set(before) | set(after)):
        old = before.get(category_id, 0)
        new = after.get(category_id, 0)
        if old == new:
            continue
        changes.append((category_id, old, new, new - old))

    changes.sort(key=lambda item: (abs(item[3]), item[0]), reverse=True)
    return changes[: max(limit, 1)]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a markdown summary for GitHub Actions runs.")
    parser.add_argument("--current-policy", type=pathlib.Path, required=True, help="Current policy_reference.json")
    parser.add_argument("--baseline-policy", type=pathlib.Path, default=None, help="Previous policy_reference.json")
    parser.add_argument("--conflicts", type=pathlib.Path, required=True, help="Current conflicts.json")
    parser.add_argument("--fetch-report", type=pathlib.Path, required=True, help="Current fetch_report.json")
    parser.add_argument("--minimums", type=pathlib.Path, default=None, help="Current min_rules.json")
    parser.add_argument("--output", type=pathlib.Path, required=True, help="Markdown output path")
    parser.add_argument("--watchlist-limit", type=int, default=10, help="Number of watchlist rows to include")
    parser.add_argument("--change-limit", type=int, default=10, help="Number of count changes to include")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    current_policy = read_json(args.current_policy)
    fetch_report = read_json(args.fetch_report)
    conflicts = read_json(args.conflicts)
    current_counts = parse_counts(current_policy)
    baseline_counts = parse_counts(read_json(args.baseline_policy)) if args.baseline_policy else {}

    minimums: dict[str, int] = {}
    warnings: dict[str, int] = {}
    if args.minimums and args.minimums.exists():
        minimums, warnings = parse_thresholds(read_json(args.minimums))

    lines: list[str] = [
        "# Ruleset Workflow Summary",
        "",
        f"- Build Time (UTC): `{current_policy.get('generated_at_utc', 'unknown')}`",
        f"- Category Count: `{len(current_counts)}`",
        (
            "- Fetch Summary: "
            f"`network={int(fetch_report.get('network_success_count', 0))}, "
            f"offline_cache={int(fetch_report.get('offline_cache_count', 0))}, "
            f"fallback_cache={int(fetch_report.get('fallback_cache_count', 0))}, "
            f"url_count={int(fetch_report.get('url_count', 0))}`"
        ),
        (
            "- Conflict Summary: "
            f"`total={int(conflicts.get('conflict_count', 0))}, "
            f"cross_action={int(conflicts.get('cross_action_conflict_count', 0))}, "
            f"high={int(conflicts.get('high_severity_conflict_count', 0))}, "
            f"medium={int(conflicts.get('medium_severity_conflict_count', 0))}, "
            f"low={int(conflicts.get('low_severity_conflict_count', 0))}`"
        ),
    ]

    if minimums:
        lines.extend(
            [
                "",
                "## Lowest Threshold Headroom",
                "",
                "| Category | Current | Minimum | Warning | Headroom |",
                "|---|---:|---:|---:|---:|",
            ]
        )
        for row in build_watchlist(current_counts, minimums, warnings, args.watchlist_limit):
            warning = row["warning"] if row["warning"] is not None else ""
            lines.append(
                f"| `{row['id']}` | {row['current']} | {row['minimum']} | {warning} | {row['headroom']} |"
            )

    if baseline_counts:
        changes = diff_counts(baseline_counts, current_counts, args.change_limit)
        lines.extend(["", "## Top Rule Count Changes", ""])
        if changes:
            for category_id, old, new, delta in changes:
                lines.append(f"- `{category_id}`: {old} -> {new} ({delta:+d})")
        else:
            lines.append("- none")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    print(f"[run-summary] wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
