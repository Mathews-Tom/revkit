"""Generate S0 fixture schemas or validate a final result against committed bytes."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import TextIO

ASSIGNED = ("delivery.py", "display.py")
FIELDS = {"path", "verdict", "line", "excerpt", "note"}


def schema(omission: bool) -> dict[str, object]:
    complete: dict[str, object] = {"type": "boolean"}
    fields: dict[str, dict[str, object]] = {
        "path": {"type": "string", "enum": list(ASSIGNED)},
        "verdict": {"type": "string", "enum": ["finding", "clean"]},
        "line": {"type": "integer"},
        "excerpt": {"type": "string"},
        "note": {"type": "string"},
    }
    rows: dict[str, object] = {
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": False,
            "required": sorted(FIELDS),
            "properties": fields,
        },
    }
    if omission:
        complete["enum"] = [True]
        for name, value in zip(("path", "verdict", "line", "excerpt"),
                               ("display.py", "clean", 0, "")):
            fields[name]["enum"] = [value]
        rows.update(minItems=1, maxItems=1)
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["complete", "verdicts"],
        "properties": {"complete": complete, "verdicts": rows},
    }


def validate(stream: TextIO, pinned: dict[str, list[str]]) -> str:
    try:
        data = json.load(stream)
    except ValueError:
        return "invalid JSON"
    if (not isinstance(data, dict) or set(data) != {"complete", "verdicts"}
            or data["complete"] is not True or not isinstance(data["verdicts"], list)):
        return "no typed completion"
    settled: set[str] = set()
    finding = False
    for row in data["verdicts"]:
        if not isinstance(row, dict) or set(row) != FIELDS:
            return "invalid verdict shape"
        path, kind, line, excerpt, note = (row[k] for k in
                                           ("path", "verdict", "line", "excerpt", "note"))
        if (not isinstance(path, str) or path not in pinned or path in settled
                or type(line) is not int or not isinstance(excerpt, str)
                or not isinstance(note, str)):
            return "invalid or duplicate verdict"
        if kind == "finding":
            lines = pinned[path]
            if not 1 <= line <= len(lines) or excerpt != lines[line - 1] or not note.strip():
                return "invalid anchor"
            finding = True
        elif kind != "clean" or line != 0 or excerpt != "":
            return "invalid verdict"
        settled.add(path)
    if settled != pinned.keys():
        return "missing verdict"
    return "finding" if finding else "clean"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    schema_parser = commands.add_parser("schema")
    schema_parser.add_argument("--codex-omission", action="store_true")
    verify = commands.add_parser("validate")
    verify.add_argument("--repo", type=Path, required=True)
    verify.add_argument("--head", required=True)
    args = parser.parse_args()
    if args.command == "schema":
        print(json.dumps(schema(args.codex_omission)))
        return 0
    head = subprocess.check_output(
        ["git", "rev-parse", "--verify", "--end-of-options", f"{args.head}^{{commit}}"],
        cwd=args.repo, encoding="utf-8",
    ).strip()
    pinned = {
        path: subprocess.check_output(
            ["git", "show", f"{head}:{path}"], cwd=args.repo, encoding="utf-8",
        ).splitlines()
        for path in ASSIGNED
    }
    verdict = validate(sys.stdin, pinned)
    print(verdict)
    return {"clean": 0, "finding": 2}.get(verdict, 3)


if __name__ == "__main__":
    raise SystemExit(main())
