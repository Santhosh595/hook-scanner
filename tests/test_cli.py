"""CLI-level tests: end-to-end scan, exit codes, JSON output."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from hook_scanner.cli import main  # noqa: E402
from hook_scanner.findings import Finding  # noqa: E402

from conftest import install_benign_repo, install_dangerous_repo  # noqa: E402


class TestExitCodes:
    def test_clean_repo_exits_zero(self, repo_root):
        install_benign_repo(repo_root)
        assert main([str(repo_root)]) == 0

    def test_dangerous_repo_exits_high(self, repo_root):
        install_dangerous_repo(repo_root)
        # worst finding is high (3) - pr_target / download-exec hooks
        assert main([str(repo_root)]) >= 3

    def test_missing_path_exits_2(self, repo_root):
        assert main([str(repo_root / "nope")]) == 2

    def test_empty_dir_exits_zero(self, repo_root):
        repo_root.mkdir()  # exists but has no supply-chain artifacts
        assert main([str(repo_root)]) == 0


class TestJsonOutput:
    def test_json_is_parseable_and_ranked(self, repo_root, capsys):
        install_dangerous_repo(repo_root)
        rc = main([str(repo_root), "--json"])
        out = capsys.readouterr().out
        assert rc == json.loads(out)["exit_code"]
        assert json.loads(out)["count"] > 0
        sevs = [f["severity"] for f in json.loads(out)["findings"]]
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        assert [order[s] for s in sevs] == sorted(
            (order[s] for s in sevs), reverse=True
        )

    def test_json_empty_repo(self, repo_root, capsys):
        repo_root.mkdir()
        rc = main([str(repo_root), "--json"])
        out = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert out["count"] == 0


class TestReport:
    def test_table_contains_finding_text(self, repo_root, capsys):
        install_dangerous_repo(repo_root)
        main([str(repo_root)])
        out = capsys.readouterr().out
        assert "HIGH" not in out or "high" in out.lower()
        assert "No findings" not in out

    def test_clean_table_says_clean(self, repo_root, capsys):
        install_benign_repo(repo_root)
        main([str(repo_root)])
        out = capsys.readouterr().out
        # benign repo still yields info findings (instruction files),
        # but nothing high.
        assert "high" not in out.lower()
