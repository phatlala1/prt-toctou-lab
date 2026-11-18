#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def request(opener: urllib.request.OpenerDirector, url: str, *, method: str = "GET", data: bytes | None = None, headers: dict[str, str] | None = None) -> tuple[int, str, dict[str, str]]:
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with opener.open(req, timeout=10) as response:
            return response.status, response.read().decode("utf-8", "replace"), dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace"), dict(exc.headers.items())


def wait_for_health(base: str) -> None:
    opener = urllib.request.build_opener()
    deadline = time.time() + 60
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            status, _, _ = request(opener, base + "/health")
            if status == 200:
                return
        except Exception as exc:  # pragma: no cover - diagnostic path
            last_error = exc
        time.sleep(0.5)
    raise RuntimeError(f"server did not become healthy: {last_error}")


def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def urlencoded(values: list[tuple[str, str]]) -> tuple[bytes, str]:
    return urllib.parse.urlencode(values).encode(), "application/x-www-form-urlencoded"


def multipart(*, include_file: bool, multiple_files: bool = False) -> tuple[bytes, str]:
    boundary = "----R61Boundary7MA4YWxkTrZu0gW"
    pieces: list[bytes] = []

    def add_field(name: str, value: str) -> None:
        pieces.extend([
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
            value.encode(),
            b"\r\n",
        ])

    def add_file(name: str, filename: str, content: bytes) -> None:
        pieces.extend([
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode(),
            b"Content-Type: text/plain\r\n\r\n",
            content,
            b"\r\n",
        ])

    add_field("value", "r61-marker")
    if include_file:
        if multiple_files:
            add_file("file1", "one.txt", b"one")
            add_file("file2", "two.txt", b"two")
        else:
            add_file("file", "marker.txt", b"r61-file-marker")
    pieces.append(f"--{boundary}--\r\n".encode())
    return b"".join(pieces), f"multipart/form-data; boundary={boundary}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    base = args.base.rstrip("/")
    log_path = Path(args.log)
    out_path = Path(args.out)
    wait_for_health(base)

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    token_status, token_body, _ = request(opener, base + "/token")
    if token_status != 200:
        raise RuntimeError(f"token endpoint returned {token_status}: {token_body}")
    token_document = json.loads(token_body)
    request_token = token_document["requestToken"]
    header_name = token_document["headerName"]

    metadata_status, metadata_body, _ = request(opener, base + "/metadata")
    if metadata_status != 200:
        raise RuntimeError(f"metadata endpoint returned {metadata_status}: {metadata_body}")
    metadata = json.loads(metadata_body)
    antiforgery_by_route = {item["route"]: item["antiforgery"] for item in metadata}

    ordinary_cases: dict[str, list[tuple[str, str]]] = {
        "/fromform-string": [("value", "r61-marker")],
        "/fromform-int": [("value", "61")],
        "/fromform-nullable-int": [("value", "61")],
        "/fromform-string-array": [("value", "alpha"), ("value", "beta")],
        "/fromform-guid": [("value", "8c2af121-6a74-40f7-8c50-189bb8b0a061")],
        "/fromform-stringvalues": [("value", "alpha"), ("value", "beta")],
        "/form-collection": [("value", "r61-marker")],
        "/as-parameters": [("value", "r61-marker")],
        "/custom-fromform": [("value", "r61-marker")],
        "/derived-fromform": [("value", "r61-marker")],
    }

    cases: list[dict[str, Any]] = []
    for route, values in ordinary_cases.items():
        body, content_type = urlencoded(values)
        cases.append({"route": route, "body": body, "contentType": content_type})

    body, content_type = multipart(include_file=True)
    cases.append({"route": "/form-file", "body": body, "contentType": content_type})

    body, content_type = multipart(include_file=True, multiple_files=True)
    cases.append({"route": "/form-files", "body": body, "contentType": content_type})

    results: list[dict[str, Any]] = []
    for case in cases:
        route = case["route"]
        body = case["body"]
        content_type = case["contentType"]

        before_attack = count_lines(log_path)
        attack_status, attack_body, _ = request(
            opener,
            base + route,
            method="POST",
            data=body,
            headers={
                "Content-Type": content_type,
                "Origin": "https://attacker.example",
                "Sec-Fetch-Site": "cross-site",
                "User-Agent": "R61-Antiforgery-Probe/1.0",
            },
        )
        after_attack = count_lines(log_path)

        before_control = after_attack
        control_status, control_body, _ = request(
            opener,
            base + route,
            method="POST",
            data=body,
            headers={
                "Content-Type": content_type,
                "Origin": base,
                "Sec-Fetch-Site": "same-origin",
                "User-Agent": "R61-Antiforgery-Probe/1.0",
                header_name: request_token,
            },
        )
        after_control = count_lines(log_path)

        attack_invocations = after_attack - before_attack
        control_invocations = after_control - before_control
        results.append({
            "route": route,
            "antiforgeryMetadata": antiforgery_by_route.get(route),
            "attack": {
                "status": attack_status,
                "handlerInvocations": attack_invocations,
                "body": attack_body[:500],
            },
            "validControl": {
                "status": control_status,
                "handlerInvocations": control_invocations,
                "body": control_body[:500],
            },
            "bypass": attack_invocations > 0 or 200 <= attack_status < 300,
            "controlPassed": control_status == 200 and control_invocations == 1,
        })

    output = {
        "mode": args.mode,
        "base": base,
        "runtime": os.environ.get("R61_RUNTIME", "unknown"),
        "metadata": metadata,
        "results": results,
        "bypassCandidates": [item["route"] for item in results if item["bypass"]],
        "failedControls": [item["route"] for item in results if not item["controlPassed"]],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
