"""Secret scanning logic - detects leaked credentials and secrets in repository files."""

from __future__ import annotations

import fnmatch
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from leakfix.utils import check_gitleaks_installed, get_repo_root


@dataclass
class Finding:
    """Represents a single secret finding from the scanner."""

    secret_value: str
    file: str
    line: int
    commit: str
    author: str
    date: str
    rule_id: str
    entropy: float
    severity: str


def _derive_severity(rule_id: str, entropy: float) -> str:
    """Derive severity from rule_id and entropy. Gitleaks does not provide severity."""
    high_rules = {
        "generic-api-key",
        "generic-high-entropy",
        "aws-access-key",
        "aws-secret-key",
        "github-pat",
        "gitlab-pat",
        "slack-token",
        "private-key",
        "private-key-pem",
        "openssh-private-key",
    }
    if rule_id.lower() in high_rules or entropy >= 4.5:
        return "high"
    if entropy >= 3.5:
        return "medium"
    return "low"


def _load_leakfixignore(repo_root: Path) -> list[str]:
    """Load patterns from .leakfixignore file (gitignore-style)."""
    ignore_file = repo_root / ".leakfixignore"
    if not ignore_file.exists():
        return []
    patterns = []
    for line in ignore_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def _is_ignored(file_path: str, patterns: list[str], repo_root: Path) -> bool:
    """Check if a file matches any .leakfixignore pattern."""
    try:
        path = Path(file_path)
        if not path.is_absolute():
            path = (repo_root / path).resolve()
        rel_path = path.relative_to(repo_root)
    except (ValueError, OSError):
        return False
    path_str = str(rel_path).replace("\\", "/")
    for pattern in patterns:
        if fnmatch.fnmatch(path_str, pattern):
            return True
        if fnmatch.fnmatch(path_str, f"**/{pattern}"):
            return True
        if pattern.endswith("/") and path_str.startswith(pattern.rstrip("/")):
            return True
    return False


class Scanner:
    """Wraps gitleaks to provide a clean, unified scanning interface."""

    def __init__(self, source: Path | str | None = None):
        self.source = Path(source or ".").resolve()
        self.repo_root = get_repo_root(self.source) or self.source
        self._skipped_untracked: list[Finding] = []
        self._untracked_files_warned: set[str] = set()

    def get_tracked_files(self) -> set[str]:
        """Return set of relative paths tracked by git (via git ls-files)."""
        try:
            result = subprocess.run(
                ["git", "ls-files"],
                capture_output=True,
                text=True,
                cwd=str(self.repo_root),
                timeout=30,
            )
            if result.returncode != 0:
                return set()
            return {
                line.strip().replace("\\", "/")
                for line in result.stdout.splitlines()
                if line.strip()
            }
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            return set()

    def scan_working_directory(self, include_untracked: bool = False) -> list[Finding]:
        """Scan files on disk. By default only scans git-tracked files."""
        findings: list[Finding] = []
        findings.extend(self._run_gitleaks(["detect", "--no-git"]))
        findings = self._dedupe_findings(self._filter_ignored(findings))

        if include_untracked:
            return findings

        tracked = self.get_tracked_files()
        if not tracked:
            return findings

        passed: list[Finding] = []
        skipped: list[Finding] = []
        for f in findings:
            if f.file in tracked:
                passed.append(f)
            else:
                skipped.append(f)

        self._skipped_untracked.extend(skipped)
        self._untracked_files_warned.update(f.file for f in skipped)
        return passed

    def scan_staged(self) -> list[Finding]:
        """Scan only staged files (for pre-commit hook)."""
        findings = self._run_gitleaks(["protect", "--staged"])
        return self._dedupe_findings(self._filter_ignored(findings))

    def scan_history(self) -> list[Finding]:
        """Scan full git history."""
        findings = self._run_gitleaks(["detect"])
        return self._filter_ignored(findings)

    def scan_all(self, include_untracked: bool = False) -> list[Finding]:
        """Scan both working directory and git history."""
        findings = self.scan_working_directory(include_untracked=include_untracked) + self.scan_history()
        return self._dedupe_findings(findings)

    def _get_gitleaks_config_path(self) -> Path | None:
        """Return path to gitleaks config."""
        repo_config = self.repo_root / ".gitleaks.toml"
        if repo_config.exists():
            return None
        repo_config_yml = self.repo_root / ".gitleaks.yml"
        if repo_config_yml.exists():
            return None
        bundled = Path(__file__).parent / "gitleaks-extended.toml"
        if bundled.exists():
            return bundled
        return None

    def _run_gitleaks(self, args: list[str]) -> list[Finding]:
        """Run gitleaks with given subcommand and args, return parsed findings."""
        if not check_gitleaks_installed():
            raise FileNotFoundError(
                "gitleaks not found. Install with: brew install gitleaks"
            )
        cmd = [
            "gitleaks",
            *args,
            "--source",
            str(self.source),
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--no-banner",
        ]
        config_path = self._get_gitleaks_config_path()
        if config_path is not None:
            cmd.extend(["--config", str(config_path)])
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(self.source),
                timeout=300,
            )
            output = result.stdout or result.stderr or ""
            return self._parse_gitleaks_output(output)
        except subprocess.TimeoutExpired:
            return []
        except (subprocess.SubprocessError, FileNotFoundError):
            return []

    def _normalize_file_path(self, file_path: str) -> str:
        """Normalize file path to relative (relative to repo_root) for consistent deduplication."""
        if not file_path:
            return file_path
        try:
            p = Path(file_path)
            if p.is_absolute():
                rel = p.relative_to(self.repo_root)
            else:
                rel = p
            normalized = str(rel).replace("\\", "/")
            if normalized.startswith("./"):
                normalized = normalized[2:]
            return normalized
        except (ValueError, OSError):
            return file_path.replace("\\", "/")

    def _parse_gitleaks_output(self, json_output: str) -> list[Finding]:
        """Parse gitleaks JSON output into Finding objects."""
        findings = []
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            return findings
        if not isinstance(data, list):
            return findings
        for item in data:
            if not isinstance(item, dict):
                continue
            rule_id = item.get("RuleID", "unknown")
            entropy = float(item.get("Entropy", 0))
            file_path = self._normalize_file_path(item.get("File", ""))
            findings.append(
                Finding(
                    secret_value=item.get("Secret", item.get("Match", "")),
                    file=file_path,
                    line=int(item.get("StartLine", 0)),
                    commit=item.get("Commit", ""),
                    author=item.get("Email", item.get("Author", "")),
                    date=item.get("Date", ""),
                    rule_id=rule_id,
                    entropy=entropy,
                    severity=_derive_severity(rule_id, entropy),
                )
            )
        return findings

    def _filter_ignored(self, findings: list[Finding]) -> list[Finding]:
        """Filter out findings that match .leakfixignore patterns."""
        patterns = _load_leakfixignore(self.repo_root)
        if not patterns:
            return findings
        return [f for f in findings if not _is_ignored(f.file, patterns, self.repo_root)]

    def _dedupe_findings(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings by (file, line) only. Keep highest entropy when collision."""
        by_key: dict[tuple[str, int], Finding] = {}
        for f in findings:
            key = (f.file, f.line)
            if key not in by_key or f.entropy > by_key[key].entropy:
                by_key[key] = f
        return list(by_key.values())
