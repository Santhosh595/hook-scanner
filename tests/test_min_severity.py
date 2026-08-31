"""Unit tests for --min-severity argument parsing and filtering."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from hook_scanner.cli import main  # noqa: E402
from conftest import install_dangerous_repo  # noqa: E402


class TestMinSeverityInvalid:
    def test_invalid_value_exits_2(self, repo_root, capsys):
        install_dangerous_repo(repo_root)
        with pytest.raises(SystemExit) as exc_info:
            main([str(repo_root), "--min-severity", "invalid"])
        captured = capsys.readouterr()
        assert exc_info.value.code == 2
        assert "invalid choice" in captured.err.lower() or "unrecognized" in captured.err.lower()
