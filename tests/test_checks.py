"""Scanner-level tests: each check family on its fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hook_scanner.checks.claude_code import scan as scan_claude  # noqa: E402
from hook_scanner.checks.vscode import scan as scan_vscode  # noqa: E402
from hook_scanner.checks.npm_scripts import scan as scan_npm  # noqa: E402
from hook_scanner.checks.github_actions import scan as scan_gha  # noqa: E402
from hook_scanner.checks.instruction_files import scan as scan_inst  # noqa: E402

from conftest import install  # noqa: E402


class TestClaudeHooks:
    def test_dangerous_hooks_flagged(self, repo_root):
        install(repo_root, ".claude/settings.json", "claude_settings_danger.json")
        findings = scan_claude(repo_root)
        rules = {f.rule for f in findings}
        assert "hook_download_exec" in rules
        assert "hook_os_exec" in rules
        assert "hook_eval_run" in rules
        assert all(f.severity == "high" for f in findings)

    def test_clean_hooks_clean(self, repo_root):
        install(repo_root, ".claude/settings.json", "claude_settings_clean.json")
        assert scan_claude(repo_root) == []

    def test_local_settings_scanned_too(self, repo_root):
        install(
            repo_root,
            ".claude/settings.local.json",
            "claude_settings_danger.json",
        )
        assert scan_claude(repo_root)

    def test_malformed_json_is_error(self, repo_root):
        (repo_root / ".claude").mkdir(parents=True)
        (repo_root / ".claude" / "settings.json").write_text("{not json")
        findings = scan_claude(repo_root)
        assert findings[0].rule == "claude_settings_unreadable"
        assert findings[0].severity == "error"


class TestVscode:
    def test_dangerous_tasks_flagged(self, repo_root):
        install(repo_root, ".vscode/tasks.json", "vscode_tasks_danger.json")
        findings = scan_vscode(repo_root)
        rules = {f.rule for f in findings}
        assert "vscode_task_download_exec" in rules
        assert "vscode_task_powershell_iwr" in rules
        # eslint task is benign -> no finding for it
        assert all(f.severity in ("high", "info") for f in findings)

    def test_clean_tasks_no_findings(self, repo_root):
        install(repo_root, ".vscode/tasks.json", "vscode_tasks_clean.json")
        assert scan_vscode(repo_root) == []

    def test_extensions_recommended_info(self, repo_root):
        install(
            repo_root, ".vscode/extensions.json", "vscode_tasks_clean.json"
        )
        findings = scan_vscode(repo_root)
        assert all(f.rule == "vscode_extensions_recs" for f in findings)
        assert all(f.severity == "info" for f in findings)


class TestNpmScripts:
    def test_dangerous_scripts_flagged(self, repo_root):
        install(repo_root, "package.json", "package_danger.json")
        findings = scan_npm(repo_root)
        rules = {f.rule for f in findings}
        assert "npm_postinstall_dangerous" in rules
        assert "npm_preinstall_dangerous" in rules
        assert "npm_prepare_present" in rules  # benign but present = low
        assert "npm_test_present" not in {f.rule for f in findings}  # not lifecycle

    def test_clean_package_low_only(self, repo_root):
        install(repo_root, "package.json", "package_clean.json")
        findings = scan_npm(repo_root)
        assert findings and all(f.severity == "low" for f in findings)


class TestGithubActions:
    def test_pr_target_flagged(self, repo_root):
        install(
            repo_root, ".github/workflows/ci.yml", "workflow_pr_target.yml"
        )
        findings = scan_gha(repo_root)
        rules = {f.rule for f in findings}
        assert "actions_pr_target" in rules
        assert "actions_pr_target_secrets" in rules
        assert "actions_pin_by_tag" in rules  # checkout@v4 etc.
        assert "workflow_download_exec" in rules  # curl|bash run step

    def test_sha_pinned_clean_workflow(self, repo_root):
        install(repo_root, ".github/workflows/ci.yml", "workflow_clean.yml")
        assert scan_gha(repo_root) == []


class TestInstructionFiles:
    def test_instruction_files_flagged_info(self, repo_root):
        install(repo_root, "AGENTS.md", "AGENTS.md")
        install(repo_root, "CLAUDE.md", "CLAUDE.md")
        findings = scan_inst(repo_root)
        assert len(findings) == 2
        assert all(f.severity == "info" for f in findings)
        assert all(f.rule == "instruction_file" for f in findings)

    def test_no_files_no_findings(self, repo_root):
        assert scan_inst(repo_root) == []
