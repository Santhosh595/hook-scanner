"""Unit tests for --min-severity argument parsing and filtering.

These assert *exactly* which severities survive a threshold, by reading the
machine-readable --json output rather than matching loose substrings in the
human-readable output. A loose assertion ("high appears somewhere") passes
even when the filter is broken.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from hook_scanner.cli import main  # noqa: E402
from hook_scanner.findings import SEVERITY_RANK  # noqa: E402
from conftest import install_dangerous_repo  # noqa: E402


def _run_json(repo_root: Path, threshold: str | None = None) -> tuple[int, dict]:
    """Run the CLI with --json and return (exit_code, parsed_json)."""
    argv = [str(repo_root), "--json"]
    if threshold is not None:
        argv += ["--min-severity", threshold]
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        rc = main(argv)
    return rc, json.loads(buffer.getvalue())


class TestMinSeverityInvalid:
    def test_invalid_value_exits_2(self, repo_root, capsys):
        install_dangerous_repo(repo_root)
        with pytest.raises(SystemExit) as exc_info:
            main([str(repo_root), "--min-severity", "invalid"])
        captured = capsys.readouterr()
        assert exc_info.value.code == 2
        assert "invalid choice" in captured.err.lower() or "unrecognized" in captured.err.lower()


class TestMinSeverityFiltering:
    def test_default_threshold_reports_every_severity(self, repo_root):
        """No --min-severity must not silently drop anything."""
        install_dangerous_repo(repo_root)
        _, data = _run_json(repo_root)
        severities = {f["severity"] for f in data["findings"]}
        assert severities, "the dangerous repo must produce findings"
        # The fixture trips every family, so it must reach at least medium
        # and must carry more than one distinct severity.
        assert "medium" in severities
        assert len(severities) > 1, f"expected several severities, got {severities}"

    def test_threshold_excludes_lower_severities_exactly(self, repo_root):
        """The surviving set must be exactly those at or above the threshold."""
        install_dangerous_repo(repo_root)
        _, all_data = _run_json(repo_root, "low")
        _, med_data = _run_json(repo_root, "medium")

        all_sev = {f["severity"] for f in all_data["findings"]}
        med_sev = {f["severity"] for f in med_data["findings"]}

        assert "low" in all_sev, "fixture must produce a low finding to filter"
        assert med_sev <= all_sev
        assert "low" not in med_sev, "low must be excluded at the medium threshold"
        assert "info" not in med_sev, "info must be excluded at the medium threshold"
        for sev in med_sev:
            assert sev in {"medium", "high", "critical", "error"}, (
                f"{sev} survived the medium threshold but is below it"
            )

    def test_a_higher_threshold_never_adds_findings(self, repo_root):
        """Raising the threshold can only remove findings, never add them."""
        install_dangerous_repo(repo_root)
        counts = []
        for threshold in ("low", "medium", "high", "critical"):
            _, data = _run_json(repo_root, threshold)
            counts.append(len(data["findings"]))
        assert counts == sorted(counts, reverse=True), (
            f"finding counts must be non-increasing as the threshold rises: {counts}"
        )

    def test_critical_threshold_keeps_only_critical(self, repo_root):
        install_dangerous_repo(repo_root)
        _, data = _run_json(repo_root, "critical")
        for finding in data["findings"]:
            assert finding["severity"] == "critical"

    def test_exit_code_comes_from_the_worst_severity_in_the_run(self, repo_root):
        """The exit code is the worst severity *seen*, not the worst reported.

        This is the documented contract (README: "The exit code is the worst
        severity in the run"), and the filter is a reporting filter: raising
        the threshold hides findings from the report but does not change
        what the scanner found. A test that expected the exit code to follow
        the filter would be testing a different tool.
        """
        install_dangerous_repo(repo_root)
        rc_all, data_all = _run_json(repo_root, "low")
        rc_crit, data_crit = _run_json(repo_root, "critical")

        # The filter must change what is REPORTED.
        assert len(data_crit["findings"]) <= len(data_all["findings"])
        # But it must not change what the scanner found, so the exit code
        # stays driven by the worst severity in the run.
        assert rc_crit == rc_all, (
            f"exit code changed with the filter: {rc_all} -> {rc_crit}. "
            "The documented contract is that the exit code is the worst "
            "severity in the run, independent of the reporting threshold."
        )
        # And the exit code must be the worst severity that was found.
        worst = max(SEVERITY_RANK[f["severity"]] for f in data_all["findings"])
        assert rc_all == (0 if worst <= SEVERITY_RANK["low"] else worst)

    def test_a_benign_repo_reports_only_noise_at_every_threshold(self, repo_root):
        from conftest import install_benign_repo

        install_benign_repo(repo_root)
        for threshold in ("low", "medium", "high", "critical"):
            _, data = _run_json(repo_root, threshold)
            for finding in data["findings"]:
                assert finding["severity"] in {"info", "low"}, (
                    f"benign repo produced {finding['severity']} at threshold {threshold}"
                )
