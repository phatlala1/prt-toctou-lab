#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def supported_protocols(run):
    return [p for p in run.get("protocols", []) if p.get("supported")]


def trials(protocol):
    return protocol.get("trials", [])


def value(item, camel, pascal):
    return item.get(camel, item.get(pascal))


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: verify.py default.json revalidate.json")

    default = load(sys.argv[1])
    revalidate = load(sys.argv[2])
    d_protocols = supported_protocols(default)
    r_protocols = supported_protocols(revalidate)

    default_positive = (
        default.get("status") == "RUNTIME_POSITIVE_REVIEW_REQUIRED"
        and bool(d_protocols)
        and all(
            len(trials(p)) == 3
            and all(
                value(t, "positive", "Positive")
                and value(t, "controls", "Controls")
                for t in trials(p)
            )
            for p in d_protocols
        )
    )
    revalidate_control = (
        revalidate.get("status") == "REVALIDATION_CONTROL_PASSED"
        and bool(r_protocols)
        and all(
            len(trials(p)) == 3
            and all(
                value(t, "revalidateControl", "RevalidateControl")
                for t in trials(p)
            )
            for p in r_protocols
        )
    )

    verdict = {
        "defaultStatus": default.get("status"),
        "revalidateStatus": revalidate.get("status"),
        "defaultPositive": default_positive,
        "revalidationControlPassed": revalidate_control,
        "finalStatus": "RUNTIME_POSITIVE_REVIEW_REQUIRED" if default_positive and revalidate_control else "NOT_POSITIVE",
    }
    print(json.dumps(verdict, indent=2, sort_keys=True))
    return 10 if verdict["finalStatus"] == "RUNTIME_POSITIVE_REVIEW_REQUIRED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
