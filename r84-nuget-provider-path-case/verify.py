#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

SECRET = "R84_SYNTHETIC_SERVICE_CONNECTION_SECRET_7F92D0"
USERNAME = "R84_SYNTHETIC_USER"


def load_events(path: Path) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def cli_contains_secret(evidence: Path, name: str) -> bool:
    stdout = (evidence / f"cli-{name}.stdout").read_text(errors="replace")
    return SECRET in stdout and USERNAME in stdout


def trial_requests(events: list[dict[str, object]], trial: str) -> list[dict[str, object]]:
    return [
        event
        for event in events
        if event.get("kind") == "request" and event.get("trial") == trial
    ]


def trial_sent_secret(events: list[dict[str, object]], trial: str) -> bool:
    return any(
        event.get("decodedUsername") == USERNAME
        and event.get("decodedPassword") == SECRET
        for event in trial_requests(events, trial)
    )


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify.py <evidence-dir>")

    evidence = Path(sys.argv[1]).resolve()
    events = load_events(evidence / "server-events.jsonl")

    gates = {
        # Direct released-binary controls.
        "cliExactCredentialReturned": cli_contains_secret(evidence, "exact"),
        "cliCaseVariantCredentialReturned": cli_contains_secret(evidence, "case"),
        "cliSiblingPathCredentialDenied": not cli_contains_secret(evidence, "sibling"),
        "cliDifferentHostCredentialDenied": not cli_contains_secret(evidence, "host"),
        # End-to-end NuGet/network controls.
        "networkExactCredentialSent": trial_sent_secret(events, "exact"),
        "networkCaseVariantCredentialSent": trial_sent_secret(events, "case"),
        "networkSiblingPathCredentialDenied": not trial_sent_secret(events, "sibling"),
        "networkDifferentHostCredentialDenied": not trial_sent_secret(events, "host"),
        "exactRequestObserved": len(trial_requests(events, "exact")) > 0,
        "caseVariantRequestObserved": len(trial_requests(events, "case")) > 0,
        "siblingRequestObserved": len(trial_requests(events, "sibling")) > 0,
        "differentHostRequestObserved": len(trial_requests(events, "host")) > 0,
        "caseSensitivePathsDistinct": (
            any(event.get("path") == "/TrustedFeed/v3/index.json" for event in trial_requests(events, "exact"))
            and any(event.get("path") == "/trustedfeed/v3/index.json" for event in trial_requests(events, "case"))
        ),
    }

    control_names = [
        "cliExactCredentialReturned",
        "cliSiblingPathCredentialDenied",
        "cliDifferentHostCredentialDenied",
        "networkExactCredentialSent",
        "networkSiblingPathCredentialDenied",
        "networkDifferentHostCredentialDenied",
        "exactRequestObserved",
        "caseVariantRequestObserved",
        "siblingRequestObserved",
        "differentHostRequestObserved",
        "caseSensitivePathsDistinct",
    ]
    controls_passed = all(gates[name] for name in control_names)
    runtime_positive = (
        controls_passed
        and gates["cliCaseVariantCredentialReturned"]
        and gates["networkCaseVariantCredentialSent"]
    )

    if runtime_positive:
        status = "SUPPORTED_RELEASE_RUNTIME_POSITIVE_REVIEW_REQUIRED"
    elif controls_passed:
        status = "RUNTIME_NEGATIVE_CLOSED"
    else:
        status = "INVALID_RUNTIME"

    result = {
        "schema": "r84-nuget-provider-path-case/v1",
        "status": status,
        "runtimePositive": runtime_positive,
        "controlsPassed": controls_passed,
        "syntheticOnly": True,
        "configuredServiceConnectionEndpoint": "http://127.0.0.1:5084/TrustedFeed/v3/index.json",
        "repositoryControlledCaseVariantEndpoint": "http://127.0.0.1:5084/trustedfeed/v3/index.json",
        "securityBoundaryHypothesis": (
            "A repository author who controls NuGet.Config can cause the released Microsoft "
            "Artifacts Credential Provider to return a trusted external-feed service-connection "
            "credential to a distinct case-sensitive path on the same host."
        ),
        "claimLimit": (
            "The runtime uses an owned loopback case-sensitive feed and a synthetic credential. "
            "MSRC submission additionally requires public/private duplicate screening and a "
            "deployment model where different trust principals control case-distinct paths on one host."
        ),
        "gates": gates,
        "requestsByTrial": {
            name: trial_requests(events, name)
            for name in ("exact", "case", "sibling", "host")
        },
    }

    result_path = evidence / "result.json"
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = [
        f"status={status}",
        f"runtimePositive={str(runtime_positive).lower()}",
        f"controlsPassed={str(controls_passed).lower()}",
    ]
    summary.extend(f"gate.{name}={str(value).lower()}" for name, value in gates.items())
    (evidence / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")

    sums: list[str] = []
    for path in sorted(evidence.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS.txt":
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            sums.append(f"{digest}  {path.relative_to(evidence).as_posix()}")
    (evidence / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="ascii")

    print(json.dumps(result, indent=2, sort_keys=True))
    if runtime_positive:
        return 10
    if not controls_passed:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
