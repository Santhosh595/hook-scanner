"""Static-execution danger patterns shared by the check families.

Everything here is heuristic: a match on a command string does not prove
malice, it flags a pattern worth a human look. The patterns target the
download-and-execute chains shown up by the Keyv / Claude-Code-hook class
of supply-chain attacks (curl|bash, eval, os.system, base64 -> decode ->
run, etc).
"""

from __future__ import annotations

import re

_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "download_exec",
        re.compile(
            r"\b(?:curl|wget)\b[^\n;|]*\|\s*(?:[a-z0-9]*\s*)?(?:ba|z)?s?h\b",
            re.IGNORECASE,
        ),
        "A URL piped straight into a shell (curl|bash / wget|sh).",
    ),
    (
        "base64_decode_run",
        re.compile(
            r"base64\s+(?:-[a-zA-Z]+z|--decode|-d)\b[^\n;|]*\|\s*\w+",
            re.IGNORECASE,
        ),
        "A base64 blob decoded and executed.",
    ),
    (
        "eval_run",
        re.compile(r"\beval\b|Invoke-Expression|\bIEX\b"),
        "Arbitrary string eval (eval / Invoke-Expression).",
    ),
    (
        "os_exec",
        re.compile(
            r"\bos\.system\b|\bos\.popen\b|\bsubprocess\b|"
            r"\bexec(?:l|le|lp|v)?\(|\bsystem\(|`{1,2}[^`]+`{1,2}",
        ),
        "Python/system exec primitive in a hook command.",
    ),
    (
        "remote_code",
        re.compile(
            r"\b(?:exec|open|curl|wget|fetch)\s*\(",
            re.IGNORECASE,
        ),
        "Potential remote-code fetch inside an evaluated string.",
    ),
    (
        "powershell_iwr",
        re.compile(
            r"\bInvoke-WebRequest\b|\bInvoke-RestMethod\b|"
            r"\biwr\s|\biwr\b|-EncodedCommand",
            re.IGNORECASE,
        ),
        "PowerShell download/encode pattern.",
    ),
]


def danger_signatures(command: str) -> list[tuple[str, str]]:
    """Return [(rule_id, detail)] for every danger pattern in `command`."""
    hits: list[tuple[str, str]] = []
    for rule_id, pattern, hint in _PATTERNS:
        m = pattern.search(command)
        if m:
            hits.append((rule_id, f"{hint} Matched: {m.group(0)!r}"))
    return hits


def is_dangerous(command: str) -> bool:
    return bool(danger_signatures(command))