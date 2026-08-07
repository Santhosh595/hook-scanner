"""Informational audit of repo instruction files.

AGENTS.md / CLAUDE.md / .cursorrules are read by AI coding agents and
treated as instructions. An attacker who gets a file like this into a
repo (or a fuzzy-matching lookup) can steer an agent to run commands /
exfiltrate data. The scan itself is read-only and only surfaces the file
so a human reviews its content as a context-injection vector, since a
fully malicious payload can't be reliably detected statically.
"""
from __future__ import annotations

from pathlib import Path

from ..findings import Finding

_INSTRUCTION_FILES = ("AGENTS.md", "CLAUDE.md", ".cursorrules", "CLAUDE.txt")


def scan(repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for name in _INSTRUCTION_FILES:
        path = repo_root / name
        if not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except Exception:
            size = 0
        # Loaded into an agent's context window; flag what it is + size.
        findings.append(
            Finding(
                rule="instruction_file",
                severity="info",
                file=str(path),
                message=(
                    "Agent context/instruction file present - verify it does "
                    "not contain instructions that make an AI agent run "
                    "arbitrary commands or exfiltrate data."
                ),
                detail=(
                    f"{name} ({size} bytes) is auto-read by AI coding agents "
                    "as a context/instruction source."
                ),
                category="instruction_files",
            )
        )
    return findings