"""Static-execution danger patterns shared by the check families.

Everything here is heuristic: a match on a command string does not prove
malice, it flags a pattern worth a human look. The patterns target the
download-and-execute chains shown up by the Keyv / Claude-Code-hook class
of supply-chain attacks (curl|bash, eval, os.system, base64 -> decode ->
run, etc). The staged_dropper pattern covers the fetch-to-disk variant
(curl/wget -o ... && chmod +x ... && run) used by the 2026 trojanized-npm
RedC2 droppers, which never pipe to a shell and so evade curl|bash rules.
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
    (
        "staged_dropper",
        # Shape: fetcher writes to disk (-o/-O/--output...), the script then
        # chains (&& ; || &) into chmod +x / a numeric chmod mode, a path
        # run in command position, or a shell interpreting a written path.
        # Piped forms (curl -qO- ... | sh) stay download_exec's job.
        #
        # FP discipline (QA review, PR #3): the two branches below used to
        # fire on *any* chained numeric chmod and *any* absolute path run
        # after a fetch. That flagged routine automation like
        #   curl -o app.css https://cdn/app.css && chmod 644 app.css
        #   curl -o data.csv https://api/data.csv && /usr/bin/python3 import.py
        # So: numeric modes only match when an execute bit is set (an odd
        # octal digit — perms fixes on fetched data files don't need one),
        # and absolute-path exec only matches the locations staged droppers
        # actually use: writable staging dirs (/tmp, /var/tmp, /dev/shm),
        # home trees, or a hidden file anywhere. Running a system tool by
        # absolute path is ordinary CI/setup work, not a dropper tell.
        re.compile(
            r"\b(?:curl|wget)\b"
            r"(?=[^;&|\n]*\s(?:-[a-z]*o(?![-=])|--output-document[=\s]|--output[=\s]))"
            r".*?(?:"
            r"(?:&&|\|\||;|&)\s*(?:sudo\s+)?chmod\s+(?:\+[a-z]+(?:\s*,\s*[a-z]+)*"
            r"|(?=[0-7]{3,4})[0-7]*[1357][0-7]*)"
            r"|(?:&&|\|\||;|&)\s*(?:sudo\s+)?(?:"
            r"/(?:var/)?tmp/(?:[\w.@%+-]+/)*[\w.@%+-]+"
            r"|/dev/shm/(?:[\w.@%+-]+/)*[\w.@%+-]+"
            r"|/(?:home/[\w.@%+-]+|root)/(?:[\w.@%+-]+/)*[\w.@%+-]+"
            r"|/(?:[\w.@%+-]+/)*\.[\w.@%+-]+"
            r"|\.{1,2}/[\w@%+=:,.\-]+"
            r"|(?:ba|z|da|k)?sh\s+/(?:[\w.@%+-]+/)*[\w.@%+-]+"
            r"|(?:ba|z|da|k)?sh\s+\.{1,2}/[\w@%+=:,.\-]+"
            r"))",
            re.IGNORECASE,
        ),
        "Staged dropper: fetch to disk, then chmod/execute.",
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