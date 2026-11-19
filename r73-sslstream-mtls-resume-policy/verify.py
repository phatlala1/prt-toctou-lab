#!/usr/bin/env python3
import hashlib
import json
import sys
from pathlib import Path


def denied(sequence):
    admin = (sequence or {}).get("admin") or {}
    return not (
        admin.get("serverAuthenticated")
        and admin.get("clientAuthenticated")
        and admin.get("applicationDataSucceeded")
    )


def legitimate(sequence):
    admin = (sequence or {}).get("admin") or {}
    return bool(
        admin.get("serverAuthenticated")
        and admin.get("clientAuthenticated")
        and admin.get("applicationDataSucceeded")
        and admin.get("serverRemoteCertificatePresent")
        and admin.get("serverValidationCallbackCount", 0) >= 1
        and admin.get("serverValidationSawCertificate")
    )


def positive(sequence):
    admin = (sequence or {}).get("admin") or {}
    resumed = admin.get("serverTlsResumed") is True or admin.get("clientTlsResumed") is True
    return bool(
        sequence.get("primeResumeObserved")
        and admin.get("serverAuthenticated")
        and admin.get("clientAuthenticated")
        and admin.get("applicationDataSucceeded")
        and resumed
        and not admin.get("serverRemoteCertificatePresent")
        and admin.get("serverValidationCallbackCount", 0) == 0
        and not admin.get("clientCertificateSupplied")
    )


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: verify.py default.json revalidate.json result.json")

    default = load(sys.argv[1])
    revalidate = load(sys.argv[2])
    summary = {
        "schema": "r73-sslstream-mtls-resume-policy-verdict/v1",
        "defaultMode": default.get("mode"),
        "revalidateMode": revalidate.get("mode"),
        "protocols": {},
    }

    any_supported = False
    any_positive = False
    all_positive_controls = True
    all_revalidate_controls = True
    invalid_reasons = []

    default_by_protocol = {entry["protocol"]: entry for entry in default.get("protocols", [])}
    revalidate_by_protocol = {entry["protocol"]: entry for entry in revalidate.get("protocols", [])}

    for protocol in sorted(set(default_by_protocol) | set(revalidate_by_protocol)):
        d = default_by_protocol.get(protocol, {})
        r = revalidate_by_protocol.get(protocol, {})
        d_trials = d.get("candidateTrials", [])
        r_trials = r.get("candidateTrials", [])

        supported = not d.get("fatalError") and not r.get("fatalError")
        prime_proved = bool(d_trials) and all(trial.get("primeResumeObserved") for trial in d_trials)
        reflection_proved = bool(d_trials) and all(
            (trial.get("admin") or {}).get("serverTlsResumed") is not None
            and (trial.get("admin") or {}).get("clientTlsResumed") is not None
            for trial in d_trials
        )

        controls = {
            "strictFirstDenied": denied(d.get("strictFirst")),
            "legitimateCertificateAccepted": legitimate(d.get("legitimateClientCertificate")),
            "noResumeDenied": denied(d.get("noResume")),
            "differentTargetHostDenied": denied(d.get("differentTargetHost")),
            "differentServerCertificateDenied": denied(d.get("differentServerCertificate")),
        }
        controls_passed = supported and all(controls.values())
        positives = [positive(trial) for trial in d_trials]
        three_of_three = len(positives) == 3 and all(positives)

        revalidate_denials = [denied(trial) for trial in r_trials]
        revalidate_control_passed = (
            supported
            and len(revalidate_denials) == 3
            and all(revalidate_denials)
            and all(trial.get("primeResumeObserved") for trial in r_trials)
        )

        protocol_result = {
            "supported": supported,
            "fatalErrors": {
                "default": d.get("fatalError"),
                "revalidate": r.get("fatalError"),
            },
            "primeResumeProved": prime_proved,
            "reflectionProved": reflection_proved,
            "controls": controls,
            "controlsPassed": controls_passed,
            "candidateTrialsPositive": positives,
            "candidateThreeOfThree": three_of_three,
            "revalidateTrialsDenied": revalidate_denials,
            "revalidateControlPassed": revalidate_control_passed,
        }
        summary["protocols"][protocol] = protocol_result

        if supported:
            any_supported = True
            if not prime_proved:
                invalid_reasons.append(f"{protocol}: anonymous resumption baseline not proved")
            if not reflection_proved:
                invalid_reasons.append(f"{protocol}: TLS resumed reflection unavailable")
            if not controls_passed:
                all_positive_controls = False
            if not revalidate_control_passed:
                all_revalidate_controls = False
            if three_of_three:
                any_positive = True

    if not any_supported:
        status = "INVALID_RUNTIME"
        invalid_reasons.append("no supported protocol run")
    elif any_positive and all_positive_controls and all_revalidate_controls:
        status = "RUNTIME_POSITIVE_REVIEW_REQUIRED"
    elif invalid_reasons:
        status = "INVALID_RUNTIME"
    else:
        status = "RUNTIME_NEGATIVE_CLOSED"

    summary["verdict"] = {
        "status": status,
        "anyProtocolPositiveThreeOfThree": any_positive,
        "allDefaultControlsPassed": all_positive_controls,
        "allRevalidateControlsPassed": all_revalidate_controls,
        "invalidReasons": invalid_reasons,
    }

    output = Path(sys.argv[3])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    sums = []
    for path in sorted(output.parent.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS.txt":
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            sums.append(f"{digest}  {path.relative_to(output.parent).as_posix()}")
    (output.parent / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")

    print(json.dumps(summary["verdict"], indent=2, sort_keys=True))
    return 10 if status == "RUNTIME_POSITIVE_REVIEW_REQUIRED" else (2 if status == "INVALID_RUNTIME" else 0)


if __name__ == "__main__":
    raise SystemExit(main())
