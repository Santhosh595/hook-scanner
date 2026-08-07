"""Check modules that each audit one class of supply-chain artifact."""

from .claude_code import scan as scan_claude_hooks
from .vscode import scan as scan_vscode
from .npm_scripts import scan as scan_npm_scripts
from .github_actions import scan as scan_github_actions
from .instruction_files import scan as scan_instruction_files

__all__ = [
    "scan_claude_hooks",
    "scan_vscode",
    "scan_npm_scripts",
    "scan_github_actions",
    "scan_instruction_files",
]
