# hook-scanner

Static, **read-only** audit of AI-codetool **supply-chain risk** in a repo or
workspace. It scans the files an AI coding agent *trusts* — Claude Code hooks,
VS Code tasks/extensions, npm install scripts, GitHub Actions workflows, and
agent instruction files — and flags anything that could pull remote code and
run it inside your build or your agent's context.

Built in response to the 2026 wave of supply-chain attacks (the **Keyv** npm
worm abused GitHub-Actions provenance + planted Claude Code / VS Code hooks)
that long before that made "AI-coding-tool supply chain" the defining 2026–27
threat class.

**Stdlib only.** No third-party packages, no network access, no writes to the
target — safe to run over an arbitrary clone or `npm ci` / checkout.

## Install

```bash
git clone https://github.com/Santhosh595/hook-scanner.git
cd hook-scanner
python3 -m pip install -e .
```

Or run without installing:

```bash
python3 -m hook_scanner <path>
```

## Usage

```bash
# scan the current directory, human-readable table
hook-scanner .

# machine-readable for CI / tooling
hook-scanner --json .

# minimum severity filter to ignore lower-severity findings
hook-scanner --min-severity medium .

# exit codes:
#   0  clean, or only low/info findings (non-blocking noise)
#   2-5  worst finding severity (2 medium, 3 high, 4 critical, 5 check error)
```

### What it checks

| Family | Files | Flags |
|---|---|---|
| **Claude Code hooks** | `.claude/settings.json`, `.claude/settings.local.json` | `SessionStart/Stop`, `PreToolUse/PostToolUse`, `UserPromptSubmit` commands that `curl\|bash`, `eval`, `os.system`, decode-and-run, etc. |
| **VS Code** | `.vscode/tasks.json`, `.vscode/extensions.json` | shell tasks with download-and-execute patterns; extension recommendations flagged as squatted/malvertising surface |
| **npm/yarn** | `package.json` | `preinstall`/`install`/`postinstall`/`prepare` scripts that download-and-execute — piped (`curl\|bash`) or staged (fetch to disk, then `chmod`/execute; the Keyv worm's exact vector and the 2026 RedC2 npm-dropper shape) |
| **GitHub Actions** | `.github/workflows/*.yml|yaml` | `pull_request_target` + secrets, actions pinned by tag instead of SHA, inline download-and-exec `run:` steps |
| **Agent instruction files** | `AGENTS.md`, `CLAUDE.md`, `.cursorrules` | informational: flags the file (auto-read as agent context) for a human to eyeball as a context-injection vector |

### Severity model

Findings are ranked `info → low → medium → high → critical` (plus `error` for
a check that crashed or couldn't parse its input). The **exit code is the worst
severity** in the run, so CI can fail hard on a dangerous install script while
ignoring informational noise.

```bash
$ hook-scanner ./risk-example
  SEV      CATEGORY          FILE
  ---      --------          ----
  high     claude_code       .claude/settings.json
           Claude Code hook on 'SessionStart' runs a potentially download-and-execute command.
  high     npm               package.json
           `postinstall` runs on every install and hits 'download_exec': potential download-and-execute.
  medium   github_actions    .github/workflows/ci.yml
           Action pinned by tag/branch rather than a full SHA...
$ echo $?
3
```

## Development

```bash
python3 -m pytest tests/ -q   # fixture-based suite
```

The test suite is fixture-based and covers all five check families plus the
severity/exit-code and JSON-output contracts. Run against the `tests/fixtures/`
tree; no live repos, no network, nothing is written to the scanned targets.

## Tests

```bash
python3 -m pytest tests/
```

## License

MIT