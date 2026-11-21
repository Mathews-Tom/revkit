"""Validate S0 decision records without running a harness or certifying evidence."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Collection
from copy import deepcopy
from pathlib import Path

HARNESSES = ("omp", "claude-code", "codex", "agy")
EVIDENCE = ("none", "help", "offline-fixture", "actual-auth")
COMMON_CASES = frozenset(
    {
        "pinned_input",
        "typed_settlement",
        "bad_anchor_correction",
        "missing_verdict",
        "ambient_config_denied",
        "ambient_tool_denied",
        "read_denied",
        "write_denied",
        "egress_denied",
        "settings_unchanged",
        "no_progress_cleanup",
        "timeout_cleanup",
    }
)
CHANNEL_CASE = {"attach": "per_run_attachment", "fallback": "filtered_typed_fallback"}
CASE_IDS = COMMON_CASES.union(CHANNEL_CASE.values())
TUPLE_FIELDS = ("version", "platform", "auth_mode", "channel")
APPROVAL_TEXT = (
    "basis",
    "auth_method",
    "terms",
    "provider",
    "allowed_data",
    "allowed_egress",
    "usage_cap",
)
APPROVAL_LIMITS = (
    "max_requests",
    "max_attempts",
    "deadline_seconds",
    "max_output_bytes",
)

Record = dict[str, object]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def record(value: object, at: str, keys: Collection[str] | None = None) -> Record:
    if not isinstance(value, dict):
        raise ValueError(f"{at}: expected an object")
    if keys is not None:
        required = set(keys)
        missing = required - value.keys()
        extra = value.keys() - required
        require(
            not (missing or extra),
            f"{at}: missing {sorted(missing)}, extra {sorted(extra)}",
        )
    return value


def text(value: object, at: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{at}: expected nonblank text")
    return value


def choice(value: object, at: str, options: Collection[str]) -> str:
    result = text(value, at)
    require(result in options, f"{at}: expected one of {sorted(options)}")
    return result


def validate_approval(value: object, at: str) -> None:
    approval = record(value, at, APPROVAL_TEXT + APPROVAL_LIMITS)
    for field in APPROVAL_TEXT:
        text(approval[field], f"{at}.{field}")
    for field in APPROVAL_LIMITS:
        limit = approval[field]
        require(
            type(limit) is int and limit > 0,
            f"{at}.{field}: expected a positive integer",
        )


def validate_lane(value: object, name: str) -> str:
    lane = record(
        value,
        name,
        TUPLE_FIELDS
        + (
            "decision",
            "evidence_class",
            "reason",
            "approval",
            "model",
            "usage",
            "cases",
        ),
    )
    decision = choice(lane["decision"], f"{name}.decision", ("refusal", *CHANNEL_CASE))
    level = choice(lane["evidence_class"], f"{name}.evidence_class", EVIDENCE)
    text(lane["reason"], f"{name}.reason")
    for field in (*TUPLE_FIELDS, "model", "usage"):
        if level == "actual-auth" or lane[field] is not None:
            text(lane[field], f"{name}.{field}")
    if level == "actual-auth" or lane["approval"] is not None:
        validate_approval(lane["approval"], f"{name}.approval")
    if level == "actual-auth":
        require(
            lane["auth_mode"] == "subscription",
            f"{name}: expected actual subscription auth",
        )

    passes: set[str] = set()
    attachment_unavailable = False
    for case_id, entry in record(lane["cases"], f"{name}.cases").items():
        at = f"{name}.cases.{case_id}"
        require(case_id in CASE_IDS, f"{at}: unknown case")
        case = record(
            entry, at, ("evidence_class", "status", "observation", "reproduction")
        )
        evidence = choice(case["evidence_class"], f"{at}.evidence_class", EVIDENCE)
        require(
            EVIDENCE.index(evidence) <= EVIDENCE.index(level),
            f"{at}: exceeds lane evidence",
        )
        status = choice(
            case["status"], f"{at}.status", ("pass", "fail", "not-observed")
        )
        require(
            evidence != "none" or status == "not-observed",
            f"{at}: no evidence requires not-observed",
        )
        text(case["observation"], f"{at}.observation")
        text(case["reproduction"], f"{at}.reproduction")
        if evidence == "actual-auth" and status == "pass":
            passes.add(case_id)
        if case_id == CHANNEL_CASE["attach"]:
            attachment_unavailable = status != "pass"

    if decision != "refusal":
        require(
            level == "actual-auth", f"{name}: {decision} requires actual-auth evidence"
        )
        missing = (COMMON_CASES | {CHANNEL_CASE[decision]}) - passes
        require(
            not missing,
            f"{name}: missing actual-auth passes: {', '.join(sorted(missing))}",
        )
    if decision == "fallback":
        require(
            attachment_unavailable,
            f"{name}: fallback requires a recorded attachment non-pass",
        )
    return decision


def validate(value: object) -> str:
    matrix = record(value, "matrix", ("schema_version", "first_runtime", "harnesses"))
    version = matrix["schema_version"]
    require(type(version) is int and version == 1, "matrix: expected schema_version 1")
    lanes = record(matrix["harnesses"], "harnesses", HARNESSES)
    qualified = {
        name for name in HARNESSES if validate_lane(lanes[name], name) != "refusal"
    }

    first = record(
        matrix["first_runtime"],
        "first_runtime",
        ("decision", "harness", "reason", "next_action"),
    )
    decision = choice(first["decision"], "first_runtime.decision", ("GO", "NO-GO"))
    text(first["reason"], "first_runtime.reason")
    if decision == "GO":
        choice(first["harness"], "first_runtime.harness", qualified)
        require(first["next_action"] is None, "GO: next_action must be null")
    else:
        require(
            first["harness"] is None and not qualified,
            "NO-GO cannot select or qualify a lane",
        )
        text(first["next_action"], "first_runtime.next_action")
    return decision


def unique_object(pairs: list[tuple[str, object]]) -> Record:
    result: Record = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def self_test() -> tuple[int, int]:
    # These invented records test validation only. They are not capability evidence.
    refusal: Record = dict.fromkeys((*TUPLE_FIELDS, "approval", "model", "usage"))
    refusal.update(
        decision="refusal", evidence_class="none", reason="No lane approval", cases={}
    )
    lanes = {name: deepcopy(refusal) for name in HARNESSES}
    no_go: Record = {
        "schema_version": 1,
        "harnesses": lanes,
        "first_runtime": {
            "decision": "NO-GO",
            "harness": None,
            "reason": "No approved tuple",
            "next_action": "Approve one tuple",
        },
    }
    require(validate(no_go) == "NO-GO", "self-test: complete NO-GO was not accepted")

    case: Record = {
        "status": "pass",
        "evidence_class": "actual-auth",
        "observation": "Invented observation for validator self-test",
        "reproduction": "Invented steps for validator self-test",
    }
    lane = deepcopy(refusal)
    cases = {
        case_id: case.copy() for case_id in COMMON_CASES | {CHANNEL_CASE["attach"]}
    }
    lane.update(
        decision="attach",
        evidence_class="actual-auth",
        reason="Invented attachment for validator self-test",
        version="test-version",
        platform="test-platform",
        auth_mode="subscription",
        channel="test-channel",
        model="Unknown: synthetic fixture reports no model identity",
        usage="Unknown: synthetic fixture reports no usage counters",
        approval=dict.fromkeys(APPROVAL_TEXT, "Invented approval")
        | dict.fromkeys(APPROVAL_LIMITS, 1),
        cases=cases,
    )
    first: Record = {
        "decision": "GO",
        "harness": "omp",
        "reason": "Invented GO",
        "next_action": None,
    }
    go = no_go | {"first_runtime": first, "harnesses": lanes | {"omp": lane}}
    require(validate(go) == "GO", "self-test: complete attachment GO was not accepted")
    attachment = CHANNEL_CASE["attach"]
    fallback_cases = cases | {CHANNEL_CASE["fallback"]: case}
    fallback = lane | {
        "decision": "fallback",
        "reason": "Invented unavailable attachment; independently tested fallback",
        "cases": fallback_cases
        | {
            attachment: {
                "evidence_class": "none",
                "status": "not-observed",
                "observation": "Invented unavailable attachment prerequisite",
                "reproduction": "Unrun: synthetic report documents the missing input",
            }
        },
    }
    require(
        validate(go | {"harnesses": lanes | {"omp": fallback}}) == "GO",
        "self-test: fallback GO rejected",
    )

    invalid = {
        "help-only": lane | {"evidence_class": "help", "cases": {}},
        "offline-only": lane | {"evidence_class": "offline-fixture", "cases": {}},
        "missing evidence": lane | {"cases": {}},
        "unavailable": refusal,
        "missing approval": lane | {"approval": None},
        "missing tuple": lane | {"version": None},
        "non-subscription auth": lane | {"auth_mode": "api"},
        "unrecorded model": lane | {"model": None},
        "unrecorded usage": lane | {"usage": None},
        "offline boundary observation": lane
        | {
            "cases": cases
            | {"egress_denied": case | {"evidence_class": "offline-fixture"}}
        },
        "failed anchor correction": lane
        | {"cases": cases | {"bad_anchor_correction": case | {"status": "fail"}}},
        "unobserved descendants": lane
        | {"cases": cases | {"timeout_cleanup": case | {"status": "not-observed"}}},
        "wrong channel evidence": lane | {"decision": "fallback"},
        "fallback without attachment assessment": fallback
        | {"cases": {k: v for k, v in fallback_cases.items() if k != attachment}},
        "fallback with passing attachment": fallback | {"cases": fallback_cases},
    }
    for name, rejected_lane in invalid.items():
        try:
            validate(go | {"harnesses": lanes | {"omp": rejected_lane}})
        except ValueError:
            continue
        raise ValueError(f"self-test: accepted invalid GO ({name})")
    return 3, len(invalid)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("matrix", nargs="?", type=Path)
    args = parser.parse_args()
    try:
        if args.self_test:
            accepted, rejected = self_test()
            print(
                f"self-test: {accepted} valid decisions accepted; {rejected} invalid GO decisions rejected"
            )
        else:
            with args.matrix.open(encoding="utf-8") as stream:
                decision = validate(json.load(stream, object_pairs_hook=unique_object))
            print(
                f"matrix v1: valid {decision} record (consistency only; not certification)"
            )
    except (OSError, ValueError) as exc:
        print(f"check_matrix: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
