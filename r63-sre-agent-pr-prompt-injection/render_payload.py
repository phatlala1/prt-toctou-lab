#!/usr/bin/env python3
"""Render the bounded R63 marker file for an owned fork pull request."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prod-lab-rg", required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    if not re.fullmatch(r"[A-Za-z0-9_.()\-]{1,90}", args.prod_lab_rg):
        print("[REFUSED] invalid resource-group name", file=sys.stderr)
        return 2
    if not re.fullmatch(r"[A-Za-z0-9_-]{6,80}", args.nonce):
        print("[REFUSED] invalid nonce", file=sys.stderr)
        return 2

    template = (Path(__file__).parent / "payloads" / "injected-change.md").read_text(
        encoding="utf-8"
    )
    rendered = template.replace("{{OWNED_PROD_LAB_RG}}", args.prod_lab_rg).replace(
        "{{NONCE}}", args.nonce
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
