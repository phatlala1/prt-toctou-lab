#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def by_route(document: dict) -> dict[str, dict]:
    return {item["route"]: item for item in document["results"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rdg", required=True)
    parser.add_argument("--rdf", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    rdg = load(args.rdg)
    rdf = load(args.rdf)
    rdg_routes = by_route(rdg)
    rdf_routes = by_route(rdf)
    all_routes = sorted(set(rdg_routes) | set(rdf_routes))

    rows = []
    rdg_only_bypass = []
    any_bypass = []
    failed_controls = []
    metadata_mismatches = []

    for route in all_routes:
        generated = rdg_routes.get(route)
        runtime = rdf_routes.get(route)
        if generated is None or runtime is None:
            rows.append({"route": route, "error": "missing route in one mode"})
            continue

        row = {
            "route": route,
            "rdgMetadata": generated["antiforgeryMetadata"],
            "rdfMetadata": runtime["antiforgeryMetadata"],
            "rdgAttackStatus": generated["attack"]["status"],
            "rdfAttackStatus": runtime["attack"]["status"],
            "rdgAttackInvocations": generated["attack"]["handlerInvocations"],
            "rdfAttackInvocations": runtime["attack"]["handlerInvocations"],
            "rdgControlStatus": generated["validControl"]["status"],
            "rdfControlStatus": runtime["validControl"]["status"],
            "rdgControlInvocations": generated["validControl"]["handlerInvocations"],
            "rdfControlInvocations": runtime["validControl"]["handlerInvocations"],
        }
        rows.append(row)

        if generated["bypass"] or runtime["bypass"]:
            any_bypass.append(route)
        if generated["bypass"] and not runtime["bypass"]:
            rdg_only_bypass.append(route)
        if not generated["controlPassed"] or not runtime["controlPassed"]:
            failed_controls.append(route)
        if generated["antiforgeryMetadata"] != runtime["antiforgeryMetadata"]:
            metadata_mismatches.append(route)

    verdict = "NEGATIVE"
    if rdg_only_bypass:
        verdict = "POSITIVE_RDG_ONLY_BYPASS"
    elif any_bypass:
        verdict = "POSITIVE_COMMON_OR_RDF_BYPASS"
    elif failed_controls:
        verdict = "INCONCLUSIVE_FAILED_CONTROLS"
    elif metadata_mismatches:
        verdict = "INCONCLUSIVE_METADATA_MISMATCH"

    output = {
        "verdict": verdict,
        "rdgOnlyBypass": rdg_only_bypass,
        "anyBypass": any_bypass,
        "failedControls": failed_controls,
        "metadataMismatches": metadata_mismatches,
        "rows": rows,
    }
    Path(args.out).write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(output, indent=2, sort_keys=True))

    # The workflow remains green for negative and inconclusive results so evidence is uploaded.
    # A confirmed bypass exits nonzero to make the security signal visible.
    return 2 if verdict.startswith("POSITIVE") else 0


if __name__ == "__main__":
    raise SystemExit(main())
