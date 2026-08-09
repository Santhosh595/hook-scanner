"""Command-line entry point for hook-scanner.

Static, read-only audit of a repo/workspace for AI-codetool supply-chain
risk. Stdlib only. Exit code is the worst severity seen (see findings.py):
 0 = clean (or info/low only), 3 = high, 5 = a check itself errored.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .checks import (
    scan_claude_hooks,
    scan_vscode,
    scan_npm_scripts,
    scan_github_actions,
    scan_instruction_files,
)
from .findings import SEVERITY_RANK, by_severity, exit_code, to_json

_SCANNERS = (
    ("Claude Code hooks", scan_claude_hooks),
    ("VS Code tasks/extensions", scan_vscode),
    ("npm install scripts", scan_npm_scripts),
    ("GitHub Actions workflows", scan_github_actions),
    ("Agent instruction files", scan_instruction_files),
)


def _render_table(findings) -> str:
    """ASCII severity-ranked report. Compact, greppable, CI-friendly."""
    if not findings:
        return "  No findings - clean.\n"
    lines = [
        f"  {'SEV':<8} {'CATEGORY':<18} FILE",
        f"  {'---':<8} {'--------':<18} ----",
    ]
    for f in by_severity(findings):
        lines.append(
            f"  {f.severity:<8} {f.category:<18} {f.file}"
        )
        lines.append(f"           {f.message}")
        if f.detail:
            lines.append(f"           {f.detail}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hook-scanner",
        description=(
            "Static, read-only audit of AI-codetool supply-chain risk in a "
            "repo/workspace: Claude Code hooks, VS Code tasks/extensions, "
            "npm install scripts, GitHub Actions workflows, agent "
            "instruction files."
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="repo/workspace root to scan (default: current directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON instead of the ASCII table",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"hook-scanner {__version__}",
    )
    args = parser.parse_args(argv)

    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        print(f"hook-scanner: not a directory: {root}", file=sys.stderr)
        return 2

    findings: list = []
    for label, scanner in _SCANNERS:
        try:
            findings.extend(scanner(root))
        except Exception as exc:  # a scanner must never take the CLI down
            from .findings import Finding
            findings.append(
                Finding(
                    rule=f"{scanner.__module__}_crashed",
                    severity="error",
                    file=str(root),
                    message=f"Scanner '{label}' crashed.",
                    detail=repr(exc),
                    category="internal",
                )
            )

    if args.json:
        print(to_json(findings))
    else:
        print(_render_table(findings))

    return exit_code(findings)