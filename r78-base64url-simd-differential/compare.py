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


def semantic(record: dict[str, Any]) -> tuple[Any, ...]:
    return (
        record.get("status"),
        record.get("consumed"),
        record.get("written"),
        record.get("outputHash"),
        record.get("fullDestinationHash"),
        record.get("exceptionType"),
        record.get("prefixGuardOk"),
        record.get("suffixGuardOk"),
        record.get("tailPreserved"),
        record.get("invariantFailure"),
    )


def local_signal(record: dict[str, Any]) -> bool:
    if not record.get("prefixGuardOk", False) or not record.get("suffixGuardOk", False):
        return True
    if record.get("invariantFailure"):
        return True
    if record.get("exceptionType") is None and not record.get("tailPreserved", False):
        return True
    return False


def detail(kind: str, mode: str, record: dict[str, Any], other: dict[str, Any] | None = None) -> dict[str, Any]:
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
        "fullDestinationHash": record.get("fullDestinationHash"),
        "prefixGuardOk": record.get("prefixGuardOk"),
        "suffixGuardOk": record.get("suffixGuardOk"),
        "tailPreserved": record.get("tailPreserved"),
        "exceptionType": record.get("exceptionType"),
        "invariantFailure": record.get("invariantFailure"),
    }
    if other is not None:
        item["other"] = {
            "status": other.get("status"),
            "consumed": other.get("consumed"),
            "written": other.get("written"),
            "outputHash": other.get("outputHash"),
            "fullDestinationHash": other.get("fullDestinationHash"),
            "prefixGuardOk": other.get("prefixGuardOk"),
            "suffixGuardOk": other.get("suffixGuardOk"),
            "tailPreserved": other.get("tailPreserved"),
            "exceptionType": other.get("exceptionType"),
            "invariantFailure": other.get("invariantFailure"),
        }
    return item


def main() -> int:
    if len(sys.argv) != 6:
        print("usage: compare.py <channel> <default.json> <avx2off.json> <scalar.json> <result.json>")
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
        invalid_reasons.append(f"unexpected schemas: {sorted(str(value) for value in schemas)}")

    case_sets = {name: set(records) for name, records in maps.items()}
    if len({frozenset(cases) for cases in case_sets.values()}) != 1:
        invalid_reasons.append(
            "mode case sets differ: "
            + ", ".join(f"{name}={len(cases)}" for name, cases in case_sets.items())
        )

    default_hardware = modes["default"].get("hardware", {})
    avx2off_hardware = modes["avx2off"].get("hardware", {})
    scalar_hardware = modes["scalar"].get("hardware", {})
    if modes["default"].get("architecture") in {"X64", "x64"} and not default_hardware.get("avx2"):
        invalid_reasons.append("default x64 process did not expose AVX2")
    if avx2off_hardware.get("avx2"):
        invalid_reasons.append("AVX2-off process still reports AVX2")
    if any(
        scalar_hardware.get(name)
        for name in ("avx2", "ssse3", "sse2", "advSimd", "advSimdArm64")
    ):
        invalid_reasons.append("scalar process still reports hardware intrinsics")

    inputs = {entry["id"]: entry for entry in modes["default"].get("inputs", [])}
    public_details: list[dict[str, Any]] = []
    fresh_details: list[dict[str, Any]] = []
    counters = {
        "localSignals": 0,
        "modeDivergences": 0,
        "crossApiDivergences": 0,
        "publicKnownSignals": 0,
        "freshSignals": 0,
    }

    def classify(item: dict[str, Any], is_public: bool) -> None:
        counters["publicKnownSignals" if is_public else "freshSignals"] += 1
        target = public_details if is_public else fresh_details
        if len(target) < 250:
            target.append(item)

    # Mode-local memory and contract signals.
    for mode_name, records in maps.items():
        for record in records.values():
            if local_signal(record):
                counters["localSignals"] += 1
                classify(
                    detail("local-memory-or-contract-signal", mode_name, record),
                    bool(record.get("publicKnownRoot")),
                )

    # Hardware/scalar and Vector128/scalar semantic equivalence.
    scalar_records = maps["scalar"]
    for mode_name in ("default", "avx2off"):
        for case_id in sorted(case_sets[mode_name] & case_sets["scalar"]):
            current = maps[mode_name][case_id]
            scalar = scalar_records[case_id]
            if semantic(current) != semantic(scalar):
                counters["modeDivergences"] += 1
                classify(
                    detail("mode-divergence", f"{mode_name}-vs-scalar", current, scalar),
                    bool(current.get("publicKnownRoot") or scalar.get("publicKnownRoot")),
                )

    # UTF-8 and character APIs should agree for byte-identical ASCII inputs.
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
            if semantic(utf8) != semantic(chars):
                counters["crossApiDivergences"] += 1
                classify(
                    detail("utf8-vs-chars-divergence", mode_name, utf8, chars),
                    bool(utf8.get("publicKnownRoot") or chars.get("publicKnownRoot")),
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
        "schema": "r78-base64url-simd-comparison/v1",
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
                "summary": data.get("summary"),
            }
            for name, data in modes.items()
        },
        "caseCounts": {name: len(records) for name, records in maps.items()},
        "counters": counters,
        "publicKnownDetails": public_details,
        "freshDetails": fresh_details,
        "publicPriorArt": {
            "commit": "7ad74025fa5c5ea0f8e082fa318c1c91329fe3a1",
            "condition": "Base64Url final block, destinationLength == GetMaxDecodedLength(sourceLength) - 2, sourceLength mod 4 in {1,2}",
        },
    }

    pathlib.Path(result_path).write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "channel": channel,
        "status": status,
        "invalidReasons": invalid_reasons,
        "counters": counters,
        "caseCounts": result["caseCounts"],
        "publicExamples": public_details[:3],
        "freshExamples": fresh_details[:10],
    }, indent=2, sort_keys=True))

    if status == "FRESH_RUNTIME_POSITIVE_REVIEW_REQUIRED":
        return 10
    if status == "INVALID_RUNTIME":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
