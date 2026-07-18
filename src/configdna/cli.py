"""Command-line interface for ConfigDNA."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import compare, fingerprint


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="configdna",
        description="Fingerprint and semantically compare IOS-like network configurations.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    fingerprint_parser = subparsers.add_parser("fingerprint", help="Print a stable configuration fingerprint")
    fingerprint_parser.add_argument("config", type=Path)

    diff_parser = subparsers.add_parser("diff", help="Compare two configurations")
    diff_parser.add_argument("before", type=Path)
    diff_parser.add_argument("after", type=Path)
    diff_parser.add_argument("--json", action="store_true", help="Emit structured JSON")
    diff_parser.add_argument(
        "--fail-on-risk",
        choices=("low", "medium", "high"),
        help="Exit 1 when the comparison reaches this risk level",
    )
    return parser


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "fingerprint":
            print(fingerprint(_read(args.config)))
            return 0

        result = compare(_read(args.before), _read(args.after))
    except (OSError, UnicodeError) as exc:
        print(f"configdna: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    elif not result.changed:
        print("No semantic configuration changes detected.")
    else:
        print(f"Highest risk: {result.highest_risk}")
        for change in result.changes:
            marker = "+" if change.kind == "added" else "-"
            location = f" [{change.section}]" if change.section else ""
            print(f"{marker} {change.command}{location} ({change.risk}: {change.reason})")

    if args.fail_on_risk:
        order = {"none": 0, "low": 1, "medium": 2, "high": 3}
        return 1 if order[result.highest_risk] >= order[args.fail_on_risk] else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
