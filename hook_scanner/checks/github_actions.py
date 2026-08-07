"""Audit GitHub Actions workflows (.github/workflows/*.yml|yaml).

High-value supply-chain surface: an untrusted attacker's PR can change a
workflow file, and if that workflow runs on `pull_request_target`, it runs
in the context of the target repo's secrets - even from a fork. Pinning an
action by tag (vs SHA) lets a compromised or moved tag point anyone reusing
the workflow at arbitrary code. Both are the mechanics behind the Keyv /
comment-on-PR supply-chain class the digest keeps flagging.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..findings import Finding
from ..rules import danger_signatures

_SHA_HEX = frozenset("0123456789abcdef")


def _is_full_sha(ref: str) -> bool:
    """A full 40-hex git SHA is an immutable, supply-chain-safe pin."""
    return len(ref) == 40 and all(c in _SHA_HEX for c in ref)


def _check_uses(uses: str, file_label: str, findings: list[Finding]) -> None:
    """Check a single `uses: owner/repo@ref` cell for pin safety."""
    uses = uses.strip()
    if not uses or "@" not in uses:
        return
    ref = uses.rsplit("@", 1)[1]
    if _is_full_sha(ref):
        return  # pinned by SHA - good
    findings.append(
        Finding(
            rule="actions_pin_by_tag",
            severity="medium",
            file=file_label,
            message=(
                "Action pinned by tag/branch rather than a full SHA - the "
                "tag point can be moved by the publisher or an account "
                "takeover, changing what downstream workflows execute."
            ),
            detail=f"uses: {uses}",
            category="github_actions",
        )
    )


def _flat_uses(text: str) -> list[str]:
    """Collect every `uses:` value via a line scan (no YAML dep needed)."""
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        # YAML list entries render as "- uses: action@ref"
        if stripped.startswith("- uses:"):
            stripped = stripped[1:].strip()
        if stripped.startswith("uses:"):
            val = stripped[len("uses:"):].strip().strip("'\"")
            if val:
                out.append(val)
    return out


def scan(repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    wf_dir = repo_root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return findings

    for wf in sorted(
        p for p in wf_dir.iterdir() if p.is_file() and p.suffix in (".yml", ".yaml")
    ):
        try:
            text = wf.read_text(encoding="utf-8")
        except Exception as exc:
            findings.append(
                Finding(
                    rule="workflow_unreadable",
                    severity="error",
                    file=str(wf),
                    message="Could not read workflow file.",
                    detail=repr(exc),
                    category="github_actions",
                )
            )
            continue
        label = str(wf)
        pr_target = "pull_request_target" in text

        # 1) pull_request_target runs in the base repo's secret context even
        #    for forks -> a PR author can make code run with repo secrets.
        if pr_target:
            findings.append(
                Finding(
                    rule="actions_pr_target",
                    severity="high",
                    file=label,
                    message=(
                        "Workflow triggers on `pull_request_target`, which "
                        "executes in the base repo's privileged context on "
                        "untrusted PRs (incl. from forks)."
                    ),
                    category="github_actions",
                )
            )
            # 2) secrets flowing into that privileged context amplify the leak.
            if "secrets." in text:
                findings.append(
                    Finding(
                        rule="actions_pr_target_secrets",
                        severity="high",
                        file=label,
                        message=(
                            "`pull_request_target` combined with repo secrets "
                            "in the workflow - a PR author can influence code "
                            "that runs with access to those secrets."
                        ),
                        category="github_actions",
                    )
                )

        # 3) every uses: reference - pin-by-tag heuristic
        for uses in _flat_uses(text):
            _check_uses(uses, label, findings)

        # 4) inline `run:` shell steps with download-and-execute patterns
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith("run:"):
                continue
            cmd = stripped[4:].strip().strip("'\"")
            for rule_id, detail in danger_signatures(cmd):
                findings.append(
                    Finding(
                        rule=f"workflow_{rule_id}",
                        severity="high",
                        file=label,
                        message=(
                            "Workflow `run:` step contains a download-and-"
                            "execute pattern."
                        ),
                        detail=f"{detail} [{cmd[:160]}]",
                        category="github_actions",
                    )
                )
    return findings
