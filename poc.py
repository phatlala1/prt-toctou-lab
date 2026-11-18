#!/usr/bin/env python3
"""Local deterministic PoC for Agent Framework OpenAI Responses store=false retention.

The script binds only to 127.0.0.1, uses a synthetic in-process IChatClient,
and does not require an API key or external model.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from typing import Any
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT / "r60-agentframework-store-false" / "R60AgentFramework.csproj"
FALSE_MARKER = "R60_PRIVATE_INPUT_STORE_FALSE"
TRUE_MARKER = "R60_CONTROL_INPUT_STORE_TRUE"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reproduce store=false response and input-item retention on loopback."
    )
    parser.add_argument("--port", type=int, default=5090, help="Loopback port (default: 5090)")
    parser.add_argument("--no-build", action="store_true", help="Skip dotnet restore/build")
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Evidence directory (default: evidence-YYYYMMDD-HHMMSS)",
    )
    return parser.parse_args()


def fail(message: str, code: int = 1) -> None:
    print(f"[ERROR] {message}", file=sys.stderr)
    raise SystemExit(code)


def run_checked(command: list[str]) -> None:
    print("[RUN]", " ".join(command))
    result = subprocess.run(command, cwd=ROOT, text=True)
    if result.returncode != 0:
        fail(f"Command failed with exit code {result.returncode}: {' '.join(command)}")


def ensure_port_available(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError as exc:
            fail(f"127.0.0.1:{port} is unavailable: {exc}")


def http_request(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    timeout: float = 20.0,
) -> tuple[int, dict[str, str], bytes]:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read()


def save_exchange(
    output_dir: Path,
    name: str,
    status: int,
    headers: dict[str, str],
    body: bytes,
) -> None:
    (output_dir / f"{name}.status").write_text(f"{status}\n", encoding="utf-8")
    (output_dir / f"{name}.headers.json").write_text(
        json.dumps(headers, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / f"{name}.body.json").write_bytes(body)


def decode_json(body: bytes, label: str) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except Exception as exc:
        fail(f"{label} was not valid JSON: {exc}; body={body[:500]!r}")


def contains_value(value: Any, needle: str) -> bool:
    if isinstance(value, str):
        return needle in value
    if isinstance(value, list):
        return any(contains_value(item, needle) for item in value)
    if isinstance(value, dict):
        return any(contains_value(item, needle) for item in value.values())
    return False


def write_sha256_manifest(output_dir: Path) -> None:
    lines: list[str] = []
    for path in sorted(output_dir.rglob("*")):
        if not path.is_file() or path.name == "SHA256SUMS.txt":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(output_dir).as_posix()}")
    (output_dir / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    if not 1 <= args.port <= 65535:
        fail("Port must be between 1 and 65535")

    dotnet = shutil.which("dotnet")
    if dotnet is None:
        fail("dotnet was not found. Install .NET SDK 10 or later.")

    ensure_port_available(args.port)

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    output_dir = (args.output or ROOT / f"evidence-{timestamp}").resolve()
    output_dir.mkdir(parents=True, exist_ok=False)

    if not args.no_build:
        run_checked([dotnet, "restore", str(PROJECT)])
        run_checked([dotnet, "build", str(PROJECT), "--no-restore", "-c", "Release"])

    dotnet_info = subprocess.run(
        [dotnet, "--info"], cwd=ROOT, text=True, capture_output=True, check=False
    )
    (output_dir / "dotnet-info.txt").write_text(
        dotnet_info.stdout + dotnet_info.stderr, encoding="utf-8"
    )

    base_url = f"http://127.0.0.1:{args.port}"
    env = os.environ.copy()
    env["ASPNETCORE_URLS"] = base_url
    server_log_path = output_dir / "server.log"

    print(f"[START] Launching local host on {base_url}")
    with server_log_path.open("wb") as server_log:
        process = subprocess.Popen(
            [dotnet, "run", "--project", str(PROJECT), "--no-build", "-c", "Release"],
            cwd=ROOT,
            env=env,
            stdout=server_log,
            stderr=subprocess.STDOUT,
        )

        try:
            ready = False
            for _ in range(90):
                if process.poll() is not None:
                    break
                try:
                    status, _, _ = http_request("GET", f"{base_url}/ready", timeout=1.0)
                    if status == 200:
                        ready = True
                        break
                except Exception:
                    pass
                time.sleep(0.5)

            if not ready:
                server_log.flush()
                log_tail = server_log_path.read_text(errors="replace")[-4000:]
                fail(f"Local host did not become ready. Server log tail:\n{log_tail}")

            false_request = {
                "model": "synthetic-model",
                "metadata": {"entity_id": "assistant"},
                "input": FALSE_MARKER,
                "store": False,
                "stream": False,
            }
            true_request = {
                "model": "synthetic-model",
                "metadata": {"entity_id": "assistant"},
                "input": TRUE_MARKER,
                "store": True,
                "stream": False,
            }
            (output_dir / "request-store-false.json").write_text(
                json.dumps(false_request, indent=2) + "\n", encoding="utf-8"
            )
            (output_dir / "request-store-true.json").write_text(
                json.dumps(true_request, indent=2) + "\n", encoding="utf-8"
            )

            f_post = http_request("POST", f"{base_url}/v1/responses", false_request)
            t_post = http_request("POST", f"{base_url}/v1/responses", true_request)
            save_exchange(output_dir, "01-post-store-false", *f_post)
            save_exchange(output_dir, "02-post-store-true", *t_post)

            f_post_json = decode_json(f_post[2], "store=false POST")
            t_post_json = decode_json(t_post[2], "store=true POST")

            if f_post[0] != 200 or t_post[0] != 200:
                fail(f"Creation failed: store=false={f_post[0]}, store=true={t_post[0]}")

            false_id = f_post_json.get("id")
            true_id = t_post_json.get("id")
            if not isinstance(false_id, str) or not false_id.startswith("resp_"):
                fail(f"Invalid store=false response ID: {false_id!r}")
            if not isinstance(true_id, str) or not true_id.startswith("resp_"):
                fail(f"Invalid store=true response ID: {true_id!r}")

            f_get = http_request("GET", f"{base_url}/v1/responses/{false_id}")
            t_get = http_request("GET", f"{base_url}/v1/responses/{true_id}")
            f_items = http_request("GET", f"{base_url}/v1/responses/{false_id}/input_items")
            t_items = http_request("GET", f"{base_url}/v1/responses/{true_id}/input_items")
            save_exchange(output_dir, "03-get-store-false", *f_get)
            save_exchange(output_dir, "04-get-store-true", *t_get)
            save_exchange(output_dir, "05-input-items-store-false", *f_items)
            save_exchange(output_dir, "06-input-items-store-true", *t_items)

            f_get_json = decode_json(f_get[2], "store=false GET")
            t_get_json = decode_json(t_get[2], "store=true GET")
            f_items_json = decode_json(f_items[2], "store=false input_items")
            t_items_json = decode_json(t_items[2], "store=true input_items")

            f_delete = http_request("DELETE", f"{base_url}/v1/responses/{false_id}")
            t_delete = http_request("DELETE", f"{base_url}/v1/responses/{true_id}")
            save_exchange(output_dir, "07-delete-store-false", *f_delete)
            save_exchange(output_dir, "08-delete-store-true", *t_delete)
            f_delete_json = decode_json(f_delete[2], "store=false DELETE")
            t_delete_json = decode_json(t_delete[2], "store=true DELETE")

            f_after = http_request("GET", f"{base_url}/v1/responses/{false_id}")
            t_after = http_request("GET", f"{base_url}/v1/responses/{true_id}")
            save_exchange(output_dir, "09-get-after-delete-store-false", *f_after)
            save_exchange(output_dir, "10-get-after-delete-store-true", *t_after)

            checks = {
                "storeFalsePostReturned200": f_post[0] == 200,
                "storeFalseResponseDeclaredStoreFalse": f_post_json.get("store") is False,
                "storeFalseResponseRetrievable": f_get[0] == 200,
                "storeFalseRetrievedObjectStillDeclaresStoreFalse": (
                    isinstance(f_get_json, dict) and f_get_json.get("store") is False
                ),
                "storeFalseInputItemsRetrievable": f_items[0] == 200,
                "storeFalsePrivateInputReturned": contains_value(f_items_json, FALSE_MARKER),
                "storeFalseDeleteReturned200": f_delete[0] == 200,
                "storeFalseDeleteConfirmed": (
                    isinstance(f_delete_json, dict) and f_delete_json.get("deleted") is True
                ),
                "storeTrueControlPostReturned200": t_post[0] == 200,
                "storeTrueControlRetrievable": t_get[0] == 200,
                "storeTrueControlInputItemsRetrievable": t_items[0] == 200,
                "storeTrueControlInputReturned": contains_value(t_items_json, TRUE_MARKER),
                "storeTrueDeleteReturned200": t_delete[0] == 200,
                "storeTrueDeleteConfirmed": (
                    isinstance(t_delete_json, dict) and t_delete_json.get("deleted") is True
                ),
            }

            vulnerability_gate_names = [
                "storeFalsePostReturned200",
                "storeFalseResponseDeclaredStoreFalse",
                "storeFalseResponseRetrievable",
                "storeFalseRetrievedObjectStillDeclaresStoreFalse",
                "storeFalseInputItemsRetrievable",
                "storeFalsePrivateInputReturned",
                "storeFalseDeleteReturned200",
                "storeFalseDeleteConfirmed",
            ]
            control_gate_names = [
                "storeTrueControlPostReturned200",
                "storeTrueControlRetrievable",
                "storeTrueControlInputItemsRetrievable",
                "storeTrueControlInputReturned",
                "storeTrueDeleteReturned200",
                "storeTrueDeleteConfirmed",
            ]
            vulnerability_observed = all(checks[name] for name in vulnerability_gate_names)
            controls_passed = all(checks[name] for name in control_gate_names)

            result = {
                "schema": "r60-agentframework-store-false/local-poc-v2",
                "target": {
                    "baseUrl": base_url,
                    "packages": {
                        "Microsoft.Agents.AI.Hosting": "1.28.0-preview.261106.1",
                        "Microsoft.Agents.AI.Hosting.OpenAI": "1.28.0-alpha.261106.1",
                        "Microsoft.Extensions.AI": "10.11.0",
                    },
                },
                "ids": {"storeFalseResponseId": false_id, "storeTrueResponseId": true_id},
                "statuses": {
                    "storeFalse": {
                        "post": f_post[0],
                        "get": f_get[0],
                        "inputItems": f_items[0],
                        "delete": f_delete[0],
                        "getAfterDelete": f_after[0],
                    },
                    "storeTrueControl": {
                        "post": t_post[0],
                        "get": t_get[0],
                        "inputItems": t_items[0],
                        "delete": t_delete[0],
                        "getAfterDelete": t_after[0],
                    },
                },
                "checks": checks,
                "controlsPassed": controls_passed,
                "vulnerabilityObserved": vulnerability_observed,
                "claimLimit": (
                    "This proves unintended retention and same-partition retrieval despite "
                    "store=false. It does not by itself prove cross-user or cross-tenant access."
                ),
            }
            (output_dir / "result.json").write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            print(f"[EVIDENCE] {output_dir}")

            if not controls_passed:
                print("[INCONCLUSIVE] Matched store=true controls failed.", file=sys.stderr)
                return 3
            if vulnerability_observed:
                print(
                    "[POSITIVE] store=false response, private input items, and lifecycle state "
                    "were retrievable and deletable."
                )
                return 0

            print("[NEGATIVE/FIXED] The store=false positive gate was not met.")
            return 2
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            try:
                write_sha256_manifest(output_dir)
            except Exception as exc:
                print(f"[WARN] Could not write SHA256 manifest: {exc}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
