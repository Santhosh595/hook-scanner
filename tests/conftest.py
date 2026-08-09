"""Shared test helpers: build a disposable repo tree from fixtures."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def repo_root(tmp_path: Path) -> Path:
    """Empty repo root for scans (CLI + per-check tests share it)."""
    return tmp_path / "repo"


def install(repo_root: Path, rel_path: str, fixture_name: str) -> Path:
    """Copy one fixture file into the repo tree at rel_path."""
    dest = repo_root / rel_path
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURES / fixture_name, dest)
    return dest


def install_dangerous_repo(repo_root: Path) -> None:
    """A repo that should trigger every check family's danger path."""
    install(repo_root, ".claude/settings.json", "claude_settings_danger.json")
    install(repo_root, ".vscode/tasks.json", "vscode_tasks_danger.json")
    install(repo_root, "package.json", "package_danger.json")
    install(repo_root, ".github/workflows/ci.yml", "workflow_pr_target.yml")
    install(repo_root, "AGENTS.md", "AGENTS.md")


def install_benign_repo(repo_root: Path) -> None:
    """A repo that should only produce low/info findings (or none)."""
    install(repo_root, ".claude/settings.json", "claude_settings_clean.json")
    install(repo_root, ".vscode/tasks.json", "vscode_tasks_clean.json")
    install(repo_root, "package.json", "package_clean.json")
    install(repo_root, ".github/workflows/ci.yml", "workflow_clean.yml")
    install(repo_root, "CLAUDE.md", "CLAUDE.md")
