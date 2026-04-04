"""Pre-commit hook management for leakfix - prevent secret leaks before commit."""

from __future__ import annotations

import fnmatch
import subprocess
from pathlib import Path

from leakfix.utils import DANGEROUS_PATTERNS, get_repo_root, is_git_repo, mask_secret


class HookManager:
    """Manages pre-commit hook installation and status for leakfix."""

    HOOK_SIGNATURE = "# Installed by: leakfix install-hook"

    def __init__(self, repo_path: Path | str | None = None):
        self.repo_path = Path(repo_path or ".").resolve()
        self.repo_root = get_repo_root(self.repo_path) or self.repo_path
        self.hooks_dir = self.repo_root / ".git" / "hooks"
        self.pre_commit_path = self.hooks_dir / "pre-commit"

    def _get_hook_script(self, smart: bool = False) -> str:
        """Return the hook script content to be written to .git/hooks/pre-commit."""
        smart_flag = " --smart" if smart else ""
        return f'''#!/bin/bash
# leakfix pre-commit hook
# Installed by: leakfix install-hook
# Do not edit manually - reinstall with: leakfix install-hook

# Run leakfix scan on staged files
leakfix scan --staged --hook-mode{smart_flag}

exit_code=$?

if [ $exit_code -eq 1 ]; then
    echo ""
    echo "❌ Commit blocked: secrets detected in staged files"
    echo "   Run 'leakfix fix' to auto-remediate"
    exit 1
fi

exit 0
'''

    def _check_dangerous_files(self, staged_files: list[str]) -> list[str]:
        """Check for dangerous file patterns in staged files. Returns list of dangerous files."""
        dangerous: list[str] = []
        for f in staged_files:
            # Use basename and full path for matching
            base = Path(f).name
            path_lower = f.lower()
            base_lower = base.lower()
            for pattern in DANGEROUS_PATTERNS:
                if fnmatch.fnmatch(base_lower, pattern.lower()):
                    dangerous.append(f)
                    break
                if fnmatch.fnmatch(path_lower, pattern.lower()):
                    dangerous.append(f)
                    break
                if fnmatch.fnmatch(path_lower, f"**/{pattern.lower()}"):
                    dangerous.append(f)
                    break
                # Also check if pattern (without *) matches as substring
                pat_clean = pattern.replace("*", "").lower()
                if pat_clean and pat_clean in base_lower:
                    dangerous.append(f)
                    break
        return list(dict.fromkeys(dangerous))  # dedupe preserving order

    def _suggest_gitignore_entries(self, dangerous_files: list[str]) -> list[str]:
        """Suggest .gitignore entries for dangerous files."""
        suggestions: list[str] = []
        for f in dangerous_files:
            base = Path(f).name
            # Suggest the filename or pattern
            if base.startswith("."):
                suggestions.append(base)
            elif "*" in base or base.endswith(".json") or base.endswith(".pem"):
                suggestions.append(base)
            else:
                suggestions.append(f"**/{base}")
        return list(dict.fromkeys(suggestions))

    def install_hook(self, smart: bool = False) -> bool:
        """Install pre-commit hook at .git/hooks/pre-commit. Returns True on success."""
        if not is_git_repo(self.repo_path):
            return False
        self.hooks_dir.mkdir(parents=True, exist_ok=True)
        script = self._get_hook_script(smart=smart)
        self.pre_commit_path.write_text(script, encoding="utf-8")
        self.pre_commit_path.chmod(0o755)
        return True

    def uninstall_hook(self) -> bool:
        """Remove the pre-commit hook. Returns True if removed or wasn't ours."""
        if not self.pre_commit_path.exists():
            return True
        if not self.is_hook_installed():
            return False  # Don't remove hooks we didn't install
        self.pre_commit_path.unlink()
        return True

    def is_hook_installed(self) -> bool:
        """Check if hook exists and is ours (contains our signature)."""
        if not self.pre_commit_path.exists():
            return False
        try:
            content = self.pre_commit_path.read_text(encoding="utf-8")
            return self.HOOK_SIGNATURE in content and "leakfix" in content
        except (OSError, UnicodeDecodeError):
            return False

    def get_hook_status(self) -> dict:
        """Return detailed status: installed, path, is_ours, etc."""
        exists = self.pre_commit_path.exists()
        is_ours = self.is_hook_installed() if exists else False
        return {
            "installed": exists and is_ours,
            "path": str(self.pre_commit_path),
            "exists": exists,
            "is_ours": is_ours,
            "repo_root": str(self.repo_root),
        }

    @staticmethod
    def get_staged_files(repo_path: Path) -> list[str]:
        """Get list of staged file paths (relative to repo root)."""
        try:
            result = subprocess.run(
                ["git", "diff", "--cached", "--name-only"],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return []
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            return []
