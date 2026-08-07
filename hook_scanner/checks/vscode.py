"""Audit VS Code configuration: delegated tasks and extension trust.

`.vscode/tasks.json` can wire arbitrary shell commands to task triggers;
malicious repos ship a task file that runs a download-and-exec on load.
`.vscode/extensions.json` lists recommended extensions - largely info,
but worth surfacing because "recommended from an untrusted repo" is a
classic way to get a victim to install a squatted/malvertising extension.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..findings import Finding
from ..rules import danger_signatures

_TASKS = ".vscode/tasks.json"
_EXTENSIONS = ".vscode/extensions.json"


def scan(repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []

    tasks_path = repo_root / _TASKS
    if tasks_path.is_file():
        try:
            data = json.loads(tasks_path.read_text(encoding="utf-8"))
        except Exception as exc:
            findings.append(
                Finding(
                    rule="vscode_tasks_unreadable",
                    severity="error",
                    file=str(tasks_path),
                    message="Could not parse .vscode/tasks.json.",
                    detail=repr(exc),
                    category="vscode",
                )
            )
            data = None
        if isinstance(data, dict):
            for task in data.get("tasks", []) or []:
                _check_task(task, tasks_path, findings)

    ext_path = repo_root / _EXTENSIONS
    if ext_path.is_file():
        try:
            data = json.loads(ext_path.read_text(encoding="utf-8"))
        except Exception as exc:
            findings.append(
                Finding(
                    rule="vscode_extensions_unreadable",
                    severity="error",
                    file=str(ext_path),
                    message="Could not parse .vscode/extensions.json.",
                    detail=repr(exc),
                    category="vscode",
                )
            )
            data = None
        if isinstance(data, dict):
            recs = data.get("recommendations") or []
            if recs:
                findings.append(
                    Finding(
                        rule="vscode_extensions_recs",
                        severity="info",
                        file=str(ext_path),
                        message=(
                            "Repo recommends %d VS Code extensions; "
                            "review each id for squatted/malvertising publishers."
                        ) % len(recs),
                        detail=", ".join(str(r) for r in recs[:12]),
                        category="vscode",
                    )
                )
    return findings


def _check_task(task, tasks_path: Path, findings: list[Finding]) -> None:
    if not isinstance(task, dict):
        return
    label = task.get("label", "?")
    # finds a command either at top-level or nested in options.
    candidates = []
    if isinstance(task.get("command"), str):
        candidates.append(task["command"])
    opts = task.get("options")
    if isinstance(opts, dict) and isinstance(opts.get("command"), str):
        candidates.append(opts["command"])
    for command in candidates:
        for rule_id, detail in danger_signatures(command):
            findings.append(
                Finding(
                    rule=f"vscode_task_{rule_id}",
                    severity="high",
                    file=str(tasks_path),
                    message=(
                        f"VS Code shell task '{label}' runs a potentially "
                        "download-and-execute command."
                    ),
                    detail=f"{detail} [{command.strip()[:160]}]",
                    category="vscode",
                )
            )