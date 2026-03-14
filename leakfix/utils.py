"""Utility functions - shared helpers for file I/O, git operations, and common tasks."""

import shutil
import subprocess
from pathlib import Path


def check_gitleaks_installed() -> bool:
    """Check if gitleaks is installed and available in PATH."""
    return shutil.which("gitleaks") is not None


def check_git_filter_repo_installed() -> bool:
    """Check if git-filter-repo is installed and available in PATH."""
    return shutil.which("git-filter-repo") is not None


def get_repo_root(path: Path | str | None = None) -> Path | None:
    """Get the git repository root path. Returns None if not in a git repo."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            cwd=path or ".",
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            return Path(result.stdout.strip())
        return None
    except (subprocess.SubprocessError, FileNotFoundError):
        return None


def is_git_repo(path: Path | str | None = None) -> bool:
    """Check if the current directory (or given path) is a git repository."""
    return get_repo_root(path) is not None


def has_commits(path: Path | str | None = None) -> bool:
    """Check if the repository has any commits."""
    try:
        result = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            capture_output=True,
            text=True,
            cwd=path or ".",
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip().isdigit():
            return int(result.stdout.strip()) > 0
        return False
    except (subprocess.SubprocessError, FileNotFoundError):
        return False
