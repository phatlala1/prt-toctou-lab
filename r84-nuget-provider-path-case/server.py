#!/usr/bin/env python3
"""Owned loopback HTTPS NuGet v3 server for R84.

The server is deliberately case-sensitive. It never contacts an external
service, uses only synthetic credentials, and records whether NuGet sent
Authorization to an endpoint whose path differs from the configured
service-connection endpoint.
"""

from __future__ import annotations

import argparse
import base64
import hmac
import json
import ssl
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

EXPECTED_USERNAME = "R84_SYNTHETIC_USER"
EXPECTED_PASSWORD = "R84_SYNTHETIC_SERVICE_CONNECTION_SECRET_7F92D0"


class State:
    def __init__(self, events_path: Path) -> None:
        self.events_path = events_path
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.trial = "startup"

    def set_trial(self, trial: str) -> None:
        with self.lock:
            self.trial = trial
            self._append({"kind": "trial", "trial": trial})

    def record(self, handler: BaseHTTPRequestHandler) -> dict[str, object]:
        authorization = handler.headers.get("Authorization")
        decoded_username = None
        decoded_password = None
        decode_error = None
        if authorization and authorization.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(authorization.split(" ", 1)[1]).decode("utf-8")
                decoded_username, decoded_password = decoded.split(":", 1)
            except Exception as exc:  # evidence only
                decode_error = f"{type(exc).__name__}: {exc}"

        valid_synthetic_credential = bool(
            decoded_username is not None
            and decoded_password is not None
            and hmac.compare_digest(decoded_username, EXPECTED_USERNAME)
            and hmac.compare_digest(decoded_password, EXPECTED_PASSWORD)
        )

        event = {
            "kind": "request",
            "trial": self.trial,
            "method": handler.command,
            "rawPath": handler.path,
            "path": urlsplit(handler.path).path,
            "host": handler.headers.get("Host"),
            "authorizationPresent": authorization is not None,
            "authorizationScheme": authorization.split(" ", 1)[0] if authorization else None,
            "decodedUsername": decoded_username,
            "decodedPassword": decoded_password,
            "validSyntheticCredential": valid_synthetic_credential,
            "decodeError": decode_error,
            "tls": isinstance(handler.connection, ssl.SSLSocket),
            "tlsVersion": handler.connection.version() if isinstance(handler.connection, ssl.SSLSocket) else None,
            "userAgent": handler.headers.get("User-Agent"),
        }
        with self.lock:
            self._append(event)
        return event

    def _append(self, event: dict[str, object]) -> None:
        event = {
            "atUtc": datetime.now(timezone.utc).isoformat(),
            **event,
        }
        with self.events_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True) + "\n")


class Handler(BaseHTTPRequestHandler):
    server_version = "R84OwnedNuGet/1.0"

    @property
    def state(self) -> State:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/__trial":
            trial = parse_qs(parsed.query).get("name", ["unknown"])[0]
            self.state.set_trial(trial)
            self._send_json(200, {"trial": trial})
            return
        self._send_json(404, {"error": "not-found"})

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle_request(send_body=False)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/__health":
            self._send_json(200, {"ready": True, "tls": True})
            return
        self._handle_request(send_body=True)

    def _handle_request(self, *, send_body: bool) -> None:
        event = self.state.record(self)
        path = str(event["path"])

        # NuGet may first probe with no Authorization or an empty Basic header.
        # Reject every credential except the synthetic service-connection pair so
        # the end-to-end control proves that the credential provider was invoked.
        if not event["validSyntheticCredential"]:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="R84 owned feed"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path.endswith("/v3/index.json"):
            host = self.headers.get("Host", "r84.local")
            base_path = path[: -len("v3/index.json")]
            payload = {
                "version": "3.0.0",
                "resources": [
                    {
                        "@id": f"https://{host}{base_path}flat/",
                        "@type": "PackageBaseAddress/3.0.0",
                    }
                ],
            }
            self._send_json(200, payload, send_body=send_body)
            return

        self._send_json(404, {"error": "synthetic-package-not-found"}, send_body=send_body)

    def _send_json(self, status: int, payload: dict[str, object], *, send_body: bool = True) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body) if send_body else 0))
        self.end_headers()
        if send_body:
            self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5084)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    args = parser.parse_args()

    state = State(args.events)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.state = state  # type: ignore[attr-defined]

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
