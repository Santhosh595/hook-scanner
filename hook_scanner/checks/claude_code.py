"""Audit Claude Code hooks (.claude/settings.json, settings.local.json).

Hooks are shell commands Claude Code runs on lifecycle / tool-use events.
A repo that vendors a `.claude/settings.json` with download-and-execute
commands is exactly the vector the Keyv / Claude-Code-hook attacks used.
Hooks themselves are legitimate - we only flag ones whose command looks
like it pulls remote code and runs it.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..findings import Finding
from ..rules import danger_signatures

_HOOK_FILES = (".claude/settings.json", ".claude/settings.local.json")


def _collect_commands(node, event, out) -> None:
    """Walk a hooks structure, yielding (event, command) pairs.

    The `event` comes from the top-level hooks key and is preserved through
    nesting; inner `type`/`matcher`/`hooks` keys are not event names, so they
    must not overwrite it.
    """
    if isinstance(node, dict):
        if isinstance(node.get("command"), str):
            out.append((event, node["command"]))
        for value in node.values():
            if isinstance(value, (dict, list)):
                _collect_commands(value, event, out)
    elif isinstance(node, list):
        for item in node:
            _collect_commands(item, event, out)


def _hooks_from(settings: dict) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    hooks = settings.get("hooks")
    if isinstance(hooks, dict):
        for event, config in hooks.items():
            _collect_commands(config, event, out)
    return out


def scan(repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for name in _HOOK_FILES:
        path = repo_root / name
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # malformed / not JSON
            findings.append(
                Finding(
                    rule="claude_settings_unreadable",
                    severity="error",
                    file=str(path),
                    message=f"Could not parse {name} as JSON.",
                    detail=repr(exc),
                    category="claude_code",
                )
            )
            continue
        for event, command in _hooks_from(data):
            for rule_id, detail in danger_signatures(command):
                findings.append(
                    Finding(
                        rule=f"hook_{rule_id}",
                        severity="high",
                        file=str(path),
                        message=(
                            f"Claude Code hook on '{event or '?'}' "
                            "runs a potentially download-and-execute command."
                        ),
                        detail=f"{detail} [{command.strip()[:160]}]",
                        category="claude_code",
                    )
                )
    return findings