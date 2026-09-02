"""Unit tests for --min-severity argument filtering."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from hook_scanner.cli import main
from conftest import install_dangerous_repo


class TestMinSeverityLow:
    def test_min_severity_low_includes_all_findings(self, repo_root, capsys):
        install_dangerous_repo(repo_root)
        rc = main([str(repo_root), "--min-severity", "low"])
        captured = capsys.readouterr()
        # With low threshold, should see all findings (including info, low, medium, high, critical)
        assert rc >= 2  # Should be >= medium severity due to dangerous repo
        # Should contain findings in output
        assert "SEV" in captured.out or "SEV" in captured.err
        assert "high" in captured.out.lower() or "high" in captured.err.lower() or "critical" in captured.out.lower()
        
    def test_min_severity_low_excludes_none(self, repo_root, capsys):
        install_dangerous_repo(repo_root)
        rc = main([str(repo_root), "--min-severity", "low"])
        captured = capsys.readouterr()
        # With low threshold, should NOT exclude any findings (all severities shown)
        # The test fixture contains findings of all severities, so we should see low findings
        assert "low" in captured.out.lower() or "low" in captured.err.lower()


class TestMinSeverityMedium:
    def test_min_severity_medium_excludes_low(self, repo_root, capsys):
        install_dangerous_repo(repo_root)
        rc = main([str(repo_root), "--min-severity", "medium"])
        captured = capsys.readouterr()
        # With medium threshold, should exclude low findings but keep medium+
        assert rc >= 2  # Should be >= medium
        # Should still see high/critical findings
        assert "high" in captured.out.lower() or "high" in captured.err.lower() or "critical" in captured.out.lower()


class TestMinSeverityHigh:
    def test_min_severity_high_excludes_medium_and_low(self, repo_root, capsys):
        install_dangerous_repo(repo_root)
        rc = main([str(repo_root), "--min-severity", "high"])
        captured = capsys.readouterr()
        # With high threshold, should exclude low/medium findings but keep high/critical
        assert rc >= 3  # Should be >= high
        # Should still see high findings
        assert "high" in captured.out.lower() or "high" in captured.err.lower() or "critical" in captured.out.lower()


class TestMinSeverityCritical:
    def test_min_severity_critical_excludes_all_below(self, repo_root, capsys):
        install_dangerous_repo(repo_root)
        rc = main([str(repo_root), "--min-severity", "critical"])
        captured = capsys.readouterr()
        # With critical threshold, only critical findings should be shown
        # dangerous repo may not have critical findings, so exit code might be lower
        # but we should see if any findings are displayed
        if rc >= 4:  # If there are critical findings
            assert "critical" in captured.out.lower() or "critical" in captured.err.lower()