#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import sys
from typing import Any


def load(path: str) -> dict[str, Any]:
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def record_map(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {record["caseId"]: record for record in data["records"]}


def local_signal(record: dict[str, Any]) -> str | None:
    """Return only a memory-safety/API-bounds signal.

    Writes inside the caller-provided destination beyond bytesWritten are not
    classified here. SIMD implementations may use wider stores while remaining
    within the destination span, and bytes after bytesWritten are not part of the
    decoded result. Likewise, the earlier Convert.FromBase64String-derived
    validity oracle is intentionally ignored because it is not the Base64Url API
    contract.
    """
    if not record.get("prefixGuardOk", True) or not record.get("suffixGuardOk", True):
        return "out-of-span-guard-overwrite"

    if record.get("exceptionType") is None:
        consumed = record.get("consumed")
        written = record.get("written")
        source_length = record.get("sourceLength")
        destination_length = record.get("destinationLength")
        if not isinstance(consumed, int) or not 0 <= consumed <= source_length:
            return "consumed-out-of-range"
        if not isinstance(written, int) or not 0 <= written <= destination_length:
            return "written-out-of-range"

    return None


def semantic_signal(
    left: dict[str, Any],
    right: dict[str, Any],
) -> str | None:
    """Return only acceptance or successful-output divergence.

    Non-success statuses may legitimately consume different prefixes depending
    on SIMD width. They are diagnostic, not a vulnerability signal. A candidate
    requires one implementation to accept input that the other does not, or two
    successful decodes to return different decoded bytes.
    """
    left_exception = left.get("exceptionType")
    right_exception = right.get("exceptionType")
    if bool(left_exception) != bool(right_exception):
        return "exception-vs-result"
    if left_exception or right_exception:
        return None

    left_done = left.get("status") == "Done"
    right_done = right.get("status") == "Done"
    if left_done != right_done:
        return "acceptance-divergence"

    if left_done and right_done:
        if (
            left.get("written") != right.get("written")
            or left.get("outputHash") != right.get("outputHash")
        ):
            return "successful-output-divergence"

    return None


def detail(
    kind: str,
    mode: str,
    record: dict[str, Any],
    other: dict[str, Any] | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "kind": kind,
        "mode": mode,
        "caseId": record.get("caseId"),
        "inputId": record.get("inputId"),
        "api": record.get("api"),
        "sourceLength": record.get("sourceLength"),
        "finalBlock": record.get("finalBlock"),
        "destinationLength": record.get("destinationLength"),
        "offset": record.get("offset"),
        "publicKnownRoot": record.get("publicKnownRoot"),
        "status": record.get("status"),
        "consumed": record.get("consumed"),
        "written": record.get("written"),
        "outputHash": record.get("outputHash"),
        "prefixGuardOk": record.get("prefixGuardOk"),
        "suffixGuardOk": record.get("suffixGuardOk"),
        "exceptionType": record.get("exceptionType"),
    }
    if other is not None:
        item["other"] = {
            "status": other.get("status"),
            "consumed": other.get("consumed"),
            "written": other.get("written"),
            "outputHash": other.get("outputHash"),
            "prefixGuardOk": other.get("prefixGuardOk"),
            "suffixGuardOk": other.get("suffixGuardOk"),
            "exceptionType": other.get("exceptionType"),
        }
    return item


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: compare.py <channel> <default.json> "
            "<avx2off.json> <scalar.json> <result.json>"
        )
        return 2

    channel, default_path, avx2off_path, scalar_path, result_path = sys.argv[1:]
    modes = {
        "default": load(default_path),
        "avx2off": load(avx2off_path),
        "scalar": load(scalar_path),
    }
    maps = {name: record_map(data) for name, data in modes.items()}

    invalid_reasons: list[str] = []
    schemas = {data.get("schema") for data in modes.values()}
    if schemas != {"r78-base64url-simd-differential/v1"}:
        invalid_reasons.append(
            f"unexpected schemas: {sorted(str(value) for value in schemas)}"
        )

    case_sets = {name: set(records) for name, records in maps.items()}
    if len({frozenset(cases) for cases in case_sets.values()}) != 1:
        invalid_reasons.append(
            "mode case sets differ: "
            + ", ".join(
                f"{name}={len(cases)}" for name, cases in case_sets.items()
            )
        )

    default_hardware = modes["default"].get("hardware", {})
    avx2off_hardware = modes["avx2off"].get("hardware", {})
    scalar_hardware = modes["scalar"].get("hardware", {})
    if (
        modes["default"].get("architecture") in {"X64", "x64"}
        and not default_hardware.get("avx2")
    ):
        invalid_reasons.append("default x64 process did not expose AVX2")
    if avx2off_hardware.get("avx2"):
        invalid_reasons.append("AVX2-off process still reports AVX2")
    if any(
        scalar_hardware.get(name)
        for name in ("avx2", "ssse3", "sse2", "advSimd", "advSimdArm64")
    ):
        invalid_reasons.append("scalar process still reports hardware intrinsics")

    inputs = {
        entry["id"]: entry
        for entry in modes["default"].get("inputs", [])
    }
    public_details: list[dict[str, Any]] = []
    fresh_details: list[dict[str, Any]] = []
    counters = {
        "outOfSpanGuardOverwrites": 0,
        "boundsViolations": 0,
        "acceptanceOrSuccessfulOutputDivergences": 0,
        "crossApiAcceptanceOrOutputDivergences": 0,
        "publicKnownSignals": 0,
        "freshSignals": 0,
    }

    def classify(item: dict[str, Any], is_public: bool) -> None:
        counters["publicKnownSignals" if is_public else "freshSignals"] += 1
        target = public_details if is_public else fresh_details
        if len(target) < 250:
            target.append(item)

    # Memory-safety and public API bounds only.
    for mode_name, records in maps.items():
        for record in records.values():
            kind = local_signal(record)
            if kind is None:
                continue
            if kind == "out-of-span-guard-overwrite":
                counters["outOfSpanGuardOverwrites"] += 1
            else:
                counters["boundsViolations"] += 1
            classify(
                detail(kind, mode_name, record),
                bool(record.get("publicKnownRoot")),
            )

    # SIMD/scalar acceptance and successful-output equivalence.
    scalar_records = maps["scalar"]
    for mode_name in ("default", "avx2off"):
        for case_id in sorted(case_sets[mode_name] & case_sets["scalar"]):
            current = maps[mode_name][case_id]
            scalar = scalar_records[case_id]
            kind = semantic_signal(current, scalar)
            if kind is None:
                continue
            counters["acceptanceOrSuccessfulOutputDivergences"] += 1
            classify(
                detail(kind, f"{mode_name}-vs-scalar", current, scalar),
                bool(
                    current.get("publicKnownRoot")
                    or scalar.get("publicKnownRoot")
                ),
            )

    # UTF-8 and UTF-16 APIs should agree for byte-identical ASCII input only
    # when acceptance or successful decoded bytes differ.
    for mode_name, records in maps.items():
        groups: dict[tuple[Any, ...], dict[str, dict[str, Any]]] = {}
        for record in records.values():
            if record.get("api") not in {"Utf8", "Chars"}:
                continue
            input_info = inputs.get(record.get("inputId"), {})
            if not input_info.get("crossApiComparable"):
                continue
            key = (
                record.get("inputId"),
                record.get("finalBlock"),
                record.get("destinationLength"),
                record.get("offset"),
            )
            groups.setdefault(key, {})[record["api"]] = record

        for pair in groups.values():
            if set(pair) != {"Utf8", "Chars"}:
                continue
            utf8 = pair["Utf8"]
            chars = pair["Chars"]
            kind = semantic_signal(utf8, chars)
            if kind is None:
                continue
            counters["crossApiAcceptanceOrOutputDivergences"] += 1
            classify(
                detail(
                    f"utf8-vs-chars-{kind}",
                    mode_name,
                    utf8,
                    chars,
                ),
                bool(
                    utf8.get("publicKnownRoot")
                    or chars.get("publicKnownRoot")
                ),
            )

    if invalid_reasons:
        status = "INVALID_RUNTIME"
    elif counters["freshSignals"]:
        status = "FRESH_RUNTIME_POSITIVE_REVIEW_REQUIRED"
    elif counters["publicKnownSignals"]:
        status = "PUBLIC_KNOWN_CONTROL_ONLY"
    else:
        status = "RUNTIME_NEGATIVE_CLOSED"

    result = {
        "schema": "r78-base64url-simd-comparison/v2",
        "channel": channel,
        "status": status,
        "invalidReasons": invalid_reasons,
        "runtime": {
            name: {
                "runtime": data.get("runtime"),
                "framework": data.get("framework"),
                "os": data.get("os"),
                "architecture": data.get("architecture"),
                "hardware": data.get("hardware"),
                "rawHarnessSummary": data.get("summary"),
            }
            for name, data in modes.items()
        },
        "caseCounts": {
            name: len(records) for name, records in maps.items()
        },
        "counters": counters,
        "publicKnownDetails": public_details,
        "freshDetails": fresh_details,
        "discardedOracleAssumptions": [
            "writes inside destination after bytesWritten",
            "Convert.FromBase64String as a Base64Url validity oracle",
            "different partial progress for non-success statuses",
            "full destination scratch-byte equality across SIMD widths",
        ],
        "publicPriorArt": {
            "commit": "7ad74025fa5c5ea0f8e082fa318c1c91329fe3a1",
            "condition": (
                "Base64Url final block, destinationLength == "
                "GetMaxDecodedLength(sourceLength) - 2, "
                "sourceLength mod 4 in {1,2}"
            ),
        },
    }

    pathlib.Path(result_path).write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "channel": channel,
                "status": status,
                "invalidReasons": invalid_reasons,
                "counters": counters,
                "caseCounts": result["caseCounts"],
                "publicExamples": public_details[:5],
                "freshExamples": fresh_details[:20],
            },
            indent=2,
            sort_keys=True,
        )
    )

    if status == "FRESH_RUNTIME_POSITIVE_REVIEW_REQUIRED":
        return 10
    if status == "INVALID_RUNTIME":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
