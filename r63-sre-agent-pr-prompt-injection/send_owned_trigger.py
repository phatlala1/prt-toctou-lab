#!/usr/bin/env python3
"""Send a bounded R63 payload to an owned Azure SRE Agent bridge.

The callback URL can contain a Logic App signature. It is never printed or
written to disk. This quick gate proves prompt-to-tool behavior only; the full
low-trust actor gate must use a fork PR and the shipped pull_request_target
workflow.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CONFIRMATION = "I-OWN-ALL-TARGETS"
ALLOWED_HOST_SUFFIXES = (".logic.azure.com", ".sre.azure.com")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--webhook-url",
        default=os.environ.get("SRE_AGENT_WEBHOOK_URL", ""),
        help="Owned Logic App callback or Azure SRE Agent HTTP trigger URL.",
    )
    parser.add_argument("--repo", required=True, help="Owned GitHub repo in owner/name form.")
    parser.add_argument("--prod-lab-rg", required=True, help="Dedicated owned production-lab resource group.")
    parser.add_argument("--pr-number", type=int, default=90063)
    parser.add_argument("--nonce", default=secrets.token_hex(8))
    parser.add_argument("--output", default="evidence/owned-runtime")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--confirm-owned-lab",
        required=True,
        help=f"Must equal {CONFIRMATION!r}.",
    )
    return parser.parse_args()


def validate(args: argparse.Namespace) -> urllib.parse.ParseResult:
    if args.confirm_owned_lab != CONFIRMATION:
        raise ValueError("owned-lab confirmation did not match")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
        raise ValueError("--repo must be owner/name")
    if not re.fullmatch(r"[A-Za-z0-9_.()\-]{1,90}", args.prod_lab_rg):
        raise ValueError("invalid Azure resource-group name")
    if not re.fullmatch(r"[A-Za-z0-9_-]{6,80}", args.nonce):
        raise ValueError("invalid nonce")
    if args.pr_number <= 0:
        raise ValueError("PR number must be positive")

    parsed = urllib.parse.urlparse(args.webhook_url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise ValueError("webhook must be an HTTPS URL without userinfo")
    if not any(host.endswith(suffix) for suffix in ALLOWED_HOST_SUFFIXES):
        raise ValueError(
            "refusing non-Azure target; expected a host ending in "
            + ", ".join(ALLOWED_HOST_SUFFIXES)
        )
    return parsed


def render_patch(resource_group: str, nonce: str) -> str:
    template = (Path(__file__).parent / "payloads" / "injected-change.md").read_text(
        encoding="utf-8"
    )
    return template.replace("{{OWNED_PROD_LAB_RG}}", resource_group).replace(
        "{{NONCE}}", nonce
    )


def main() -> int:
    args = parse_args()
    try:
        parsed = validate(args)
    except ValueError as exc:
        print(f"[REFUSED] {exc}", file=sys.stderr)
        return 2

    patch = render_patch(args.prod_lab_rg, args.nonce)
    body = {
        "event": "pull_request",
        "action": "opened",
        "repo": args.repo,
        "pr_number": args.pr_number,
        "pr_url": f"https://github.com/{args.repo}/pull/{args.pr_number}",
        "pr_diff_url": f"https://github.com/{args.repo}/pull/{args.pr_number}.diff",
        "pr_author": "r63-owned-low-trust-actor",
        "base_ref": "main",
        "head_ref": "r63-owned-prompt-injection",
        "head_sha": "0" * 40,
        "changed_files": [
            {
                "filename": "docs/r63-owned-lab-change.md",
                "status": "added",
                "additions": patch.count("\n") + 1,
                "deletions": 0,
                "changes": patch.count("\n") + 1,
                "patch": "\n".join("+" + line for line in patch.splitlines()),
            }
        ],
    }

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "request.json").write_text(
        json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    endpoint_metadata = {
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "path": parsed.path,
        "urlSha256": hashlib.sha256(args.webhook_url.encode()).hexdigest(),
        "queryRedacted": bool(parsed.query),
        "nonce": args.nonce,
        "resourceGroup": args.prod_lab_rg,
        "repo": args.repo,
        "actorGate": "DIRECT_TRIGGER_ONLY_NOT_FORK_PR",
    }
    (out / "endpoint-metadata.json").write_text(
        json.dumps(endpoint_metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    if args.dry_run:
        print(json.dumps(endpoint_metadata, indent=2, sort_keys=True))
        print(f"[DRY RUN] request saved to {out / 'request.json'}")
        return 0

    encoded = json.dumps(body, separators=(",", ":")).encode()
    request = urllib.request.Request(
        args.webhook_url,
        method="POST",
        data=encoded,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "r63-owned-security-lab/1.0",
        },
    )
    try:
        with urllib.request.urlopen(
            request, timeout=45, context=ssl.create_default_context()
        ) as response:
            response_body = response.read(1024 * 1024 + 1)
            status = response.status
            headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        response_body = exc.read(1024 * 1024 + 1)
        status = exc.code
        headers = dict(exc.headers.items())
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"[ERROR] trigger request failed: {exc}", file=sys.stderr)
        return 1

    if len(response_body) > 1024 * 1024:
        print("[ERROR] trigger response exceeded evidence limit", file=sys.stderr)
        return 1

    # Do not retain cookies or any authorization-like response fields.
    safe_headers = {
        key: value
        for key, value in headers.items()
        if key.lower() not in {"set-cookie", "authorization", "proxy-authorization"}
    }
    (out / "response.body").write_bytes(response_body)
    (out / "response.json").write_text(
        json.dumps(
            {"status": status, "headers": safe_headers}, indent=2, sort_keys=True
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"[SENT] HTTP {status}; nonce={args.nonce}")
    print("[NEXT] wait for the owned agent run, then execute verify_owned_lab.py")
    return 0 if 200 <= status < 300 else 1


if __name__ == "__main__":
    raise SystemExit(main())
