#!/usr/bin/env python3
"""Audit Azure Pipelines task sources for stateless raw-output boundary risks.

The task-lib writeExternalOutput() helper creates and flushes a fresh marker
filter for every call, then writes the result to the destination without adding
a newline. A partial marker at the end of one call is therefore emitted
unchanged. This audit finds shipping task call sites where repeated or adjacent
attacker-influenced calls without explicit line termination could concatenate
into the agent command marker "##vso[".

This is a source triage tool, not a vulnerability verdict. Every hit requires a
real shipping task runtime and shipping agent parser validation.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

CALL_RE = re.compile(r"(?:(?:\btl|\btaskLib|\btasklib)\s*\.\s*)?writeExternalOutput\s*\(")
CONTROL_HINT_RE = re.compile(
    r"getInput|getPathInput|getDelimitedInput|process\.env|response|filename|fileName|"
    r"path|name|message|output|result|url|version|artifact|package|keyFilter|label|item",
    re.IGNORECASE,
)
LOOP_RE = re.compile(r"\b(for|while)\s*\(|\.forEach\s*\(|\bfor\s+\([^)]*\bof\b", re.IGNORECASE)
FUNCTION_RE = re.compile(
    r"(?:function\s+([A-Za-z_$][\w$]*)|(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{|"
    r"(?:public|private|protected)?\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*[:{])"
)


@dataclass
class CallSite:
    file: str
    line: int
    function: str | None
    argument: str
    options: str
    explicit_line_termination: bool
    direct_or_attacker_influenced: bool
    loop_context: bool
    nearby_raw_call: bool
    score: int
    context: list[str]


def _scan_call(text: str, open_paren: int) -> tuple[str, str, int] | None:
    """Return first argument, remaining arguments, and call end offset."""
    depth = 1
    i = open_paren + 1
    arg_start = i
    comma = None
    quote = None
    template = False
    escape = False
    line_comment = False
    block_comment = False

    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if line_comment:
            if ch in "\r\n":
                line_comment = False
            i += 1
            continue
        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 2
            else:
                i += 1
            continue
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
                template = False
            i += 1
            continue
        if ch == "/" and nxt == "/":
            line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            block_comment = True
            i += 2
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            template = ch == "`"
            i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                first = text[arg_start : comma if comma is not None else i].strip()
                rest = text[comma + 1 : i].strip() if comma is not None else ""
                return first, rest, i + 1
        elif ch == "," and depth == 1 and comma is None:
            comma = i
        i += 1
    return None


def _has_line_termination(expr: str) -> bool:
    compact = re.sub(r"\s+", "", expr)
    patterns = (
        r"os\.EOL",
        r"\bEOL\b",
        r"\\n",
        r"\\r",
        r"String\.fromCharCode\(10\)",
        r"String\.fromCharCode\(13\)",
    )
    return any(re.search(p, expr) for p in patterns) or compact.endswith("+'\n'") or compact.endswith('+"\n"')


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _function_at(lines: list[str], line: int) -> str | None:
    start = max(0, line - 120)
    for idx in range(line - 1, start - 1, -1):
        match = FUNCTION_RE.search(lines[idx])
        if match:
            return next((g for g in match.groups() if g), None)
    return None


def _loop_context(lines: list[str], line: int) -> bool:
    start = max(0, line - 35)
    window = "\n".join(lines[start:line])
    # This intentionally over-approximates; hits are manually reviewed.
    return bool(LOOP_RE.search(window))


def _iter_sources(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".ts", ".js"}:
            continue
        parts = set(path.parts)
        if any(part in parts for part in {"node_modules", "Tests", "test", "_generated"}):
            continue
        yield path


def audit(root: Path) -> list[CallSite]:
    findings: list[CallSite] = []
    for path in _iter_sources(root):
        try:
            text = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        matches = list(CALL_RE.finditer(text))
        if not matches:
            continue
        lines = text.splitlines()
        call_lines = [_line_number(text, m.start()) for m in matches]

        for idx, match in enumerate(matches):
            open_paren = text.find("(", match.start(), match.end())
            parsed = _scan_call(text, open_paren)
            if not parsed:
                continue
            argument, options, _end = parsed
            line = call_lines[idx]
            explicit_eol = _has_line_termination(argument)
            direct = bool(CONTROL_HINT_RE.search(argument)) or bool(
                re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", argument.strip())
            )
            loop = _loop_context(lines, line)
            nearby = any(abs(other - line) <= 20 for j, other in enumerate(call_lines) if j != idx)
            score = 0
            if not explicit_eol:
                score += 4
            if direct:
                score += 3
            if loop:
                score += 3
            if nearby:
                score += 2
            if re.search(r"source\s*:\s*['\"](?:remote|repository|childProcess)['\"]", options):
                score += 1
            if argument.strip().startswith(("'", '"', "`")) and not re.search(r"\+|\$\{", argument):
                score -= 2

            context_start = max(0, line - 6)
            context_end = min(len(lines), line + 5)
            context = [f"{n + 1}: {lines[n]}" for n in range(context_start, context_end)]
            findings.append(
                CallSite(
                    file=path.relative_to(root).as_posix(),
                    line=line,
                    function=_function_at(lines, line),
                    argument=argument[:1000],
                    options=options[:1000],
                    explicit_line_termination=explicit_eol,
                    direct_or_attacker_influenced=direct,
                    loop_context=loop,
                    nearby_raw_call=nearby,
                    score=score,
                    context=context,
                )
            )
    return sorted(findings, key=lambda f: (-f.score, f.file, f.line))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    args = parser.parse_args()

    findings = audit(args.root)
    high = [f for f in findings if f.score >= 8 and not f.explicit_line_termination]
    payload = {
        "schema": "r82-writeexternaloutput-call-boundary-audit/v1",
        "root": str(args.root.resolve()),
        "totalCalls": len(findings),
        "unterminatedCalls": sum(not f.explicit_line_termination for f in findings),
        "highPriorityCalls": len(high),
        "findings": [asdict(f) for f in findings],
    }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    md = [
        "# R82 shipping task raw-output call-boundary audit",
        "",
        f"- Total raw calls: `{payload['totalCalls']}`",
        f"- Calls without explicit EOL: `{payload['unterminatedCalls']}`",
        f"- High-priority triage hits: `{payload['highPriorityCalls']}`",
        "",
        "A hit is not a vulnerability. It must support two attacker-controlled adjacent writes on one agent log line.",
        "",
    ]
    for f in high[:100]:
        md.extend(
            [
                f"## `{f.file}:{f.line}` — score {f.score}",
                "",
                f"- Function: `{f.function or 'unknown'}`",
                f"- Argument: `{f.argument.replace('`', '\\`')}`",
                f"- Loop context: `{f.loop_context}`",
                f"- Nearby raw call: `{f.nearby_raw_call}`",
                "",
                "```text",
                *f.context,
                "```",
                "",
            ]
        )
    args.markdown.write_text("\n".join(md), encoding="utf-8")
    print(json.dumps({k: payload[k] for k in ("totalCalls", "unterminatedCalls", "highPriorityCalls")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
