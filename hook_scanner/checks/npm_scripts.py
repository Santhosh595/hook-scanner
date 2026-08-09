"""Audit npm/yarn install-time scripts (package.json).

The Keyv worm poisoned packages by abusing a package.json `postinstall` and
GitHub-Actions provenance to fetch and run code on every `npm install`. Any
of preinstall / install / postinstall / prepare runs unattended on install,
so an arbitrary command there is direct supply-chain surface.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..findings import Finding
from ..rules import danger_signatures

INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")


def scan(repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    pkg_file = repo_root / "package.json"
    if not pkg_file.is_file():
        return findings

    try:
        data = json.loads(pkg_file.read_text(encoding="utf-8"))
    except Exception as exc:
        findings.append(
            Finding(
                rule="npm_script_unreadable",
                severity="error",
                file=str(pkg_file),
                message="Could not parse package.json.",
                detail=repr(exc),
                category="npm",
            )
        )
        return findings

    scripts = data.get("scripts") or {}
    if not isinstance(scripts, dict):
        return findings

    for name in INSTALL_SCRIPTS:
        command = scripts.get(name)
        if not isinstance(command, str):
            continue
        hits = danger_signatures(command)
        if hits:
            findings.append(
                Finding(
                    rule=f"npm_{name}_dangerous",
                    severity="high",
                    file=str(pkg_file),
                    message=(
                        f"`{name}` runs on every install and hits "
                        f"'{hits[0][0]}': potential download-and-execute."
                    ),
                    detail=(
                        f"{hits[0][1]} | {command.strip()[:160]} "
                        f"({len(hits)} danger pattern(s))"
                    ),
                    category="npm",
                )
            )
        else:
            findings.append(
                Finding(
                    rule=f"npm_{name}_present",
                    severity="low",
                    file=str(pkg_file),
                    message=(
                        f"'{name}' lifecycle script runs arbitrary code on "
                        "every `npm install`. Prefer a build step with an "
                        "explicit trigger."
                    ),
                    detail=command.strip()[:160],
                    category="npm",
                )
            )
    return findings