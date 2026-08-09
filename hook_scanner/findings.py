"""hook-scanner - severity/exit-code model and finding records.

Stdlib only. A Finding is a single observation produced by one of the
static checks. Severity drives both the ranked report and the process
exit code, so CI can fail hard on a bad install script but ignore noise.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict

# Higher number = worse. Exit code == worst severity seen in a run.
SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
    "error": 5,  # a check itself crashed / could not be read
}

# Friendly ordering for the ASCII report.
_SEVERITY_DISPLAY = ["critical", "high", "medium", "low", "info", "error"]


@dataclass
class Finding:
    """One static-analysis observation.

    category: human label of the source (eg "claude_code", "npm").
    rule:     stable machine rule id (used by JSON output + tests).
    file:     path relative to the scanned root.
    severity: one of SEVERITY_RANK keys.
    message:  short human summary.
    detail:   optional longer explanation / matched snippet.
    """

    rule: str
    severity: str
    file: str
    message: str
    detail: str = ""
    category: str = ""

    def as_dict(self) -> dict:
        d = asdict(self)
        d["exit_code"] = SEVERITY_RANK[self.severity]
        return d


def exit_code(findings: list[Finding]) -> int:
    """CI-friendly exit code: 0 unless a medium-or-worse finding exists.

    info/low findings are non-blocking (ranks 0/1) so a run that only
    surfaces noise exits 0; a medium, high, critical, or error exits non-zero
    with the worst severity's rank.
    """
    if not findings:
        return 0
    worst = max(SEVERITY_RANK[f.severity] for f in findings)
    return 0 if worst <= SEVERITY_RANK["low"] else worst


def by_severity(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings, key=lambda f: SEVERITY_RANK[f.severity], reverse=True
    )


def to_json(findings: list[Finding]) -> str:
    payload = {
        "exit_code": exit_code(findings),
        "count": len(findings),
        "summary": {
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
            "info": sum(1 for f in findings if f.severity == "info"),
        },
        "findings": [f.as_dict() for f in by_severity(findings)],
    }
    return json.dumps(payload, indent=2)