"""Secret scanning logic - detects leaked credentials and secrets in repository files."""

from __future__ import annotations

import fnmatch
import json
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from leakfix.utils import check_gitleaks_installed, get_repo_root

# System/tool directories that should never be scanned for project secrets,
# even in --all mode. These are OS and toolchain directories that exist under
# a user's home directory but are not part of any project.
_DEFAULT_FS_IGNORE_PATTERNS = [
    # OS user-data directories (Linux/macOS XDG)
    ".local/",
    ".cache/",
    "Library/",
    ".Trash/",
    # Package manager caches and registries
    ".npm/",
    ".yarn/",
    ".pnpm-store/",
    ".cargo/registry/",
    ".cargo/git/",
    ".rustup/",
    ".gradle/",
    ".m2/",
    ".ivy2/",
    ".sbt/",
    # Container / orchestration tool data
    ".docker/",
    ".kube/",
    ".minikube/",
    # Python virtual environments / tooling
    ".pyenv/",
    ".virtualenvs/",
    # IDE runtime data (not project config)
    ".vscode-server/",
    ".cursor/extensions/",
    ".cursor/User/",
    # macOS system folders sometimes present in home-rooted repos
    "Applications/",
    "Movies/",
    "Music/",
    "Pictures/",
]


def check_ggshield_installed() -> bool:
    """Check if ggshield is installed."""
    return shutil.which("ggshield") is not None


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
    scanner: str = "gitleaks"  # "gitleaks", "ggshield", or "both"
    match_context: str = ""    # surrounding code line (e.g. GITLAB_TOKEN=glpat-...)


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
    """Wraps gitleaks and ggshield to provide a clean, unified scanning interface."""

    def __init__(self, source: Path | str | None = None):
        self.source = Path(source or ".").resolve()
        self.repo_root = get_repo_root(self.source) or self.source
        self._skipped_untracked: list[Finding] = []
        self._untracked_files_warned: set[str] = set()
        self._ggshield_available: bool | None = None
        self._ggshield_message_shown: bool = False

    @property
    def ggshield_available(self) -> bool:
        """Check if ggshield is available (cached)."""
        if self._ggshield_available is None:
            self._ggshield_available = check_ggshield_installed()
        return self._ggshield_available

    def get_scanner_info_message(self) -> str | None:
        """
        Return info message about scanner availability.
        Returns None if ggshield is available, otherwise returns install hint.
        """
        if self.ggshield_available:
            return None
        return "ℹ️  ggshield not found — using gitleaks only. Install: brew install ggshield"

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
        # Use dual-scanner if ggshield is available
        def gitleaks_scan():
            return self._run_gitleaks(["detect", "--no-git"])

        findings = self._scan_with_both_scanners(gitleaks_scan, ggshield_history=False)
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
        # Note: ggshield doesn't have a staged-only mode, so we use gitleaks only for staged
        findings = self._run_gitleaks(["protect", "--staged"])
        return self._dedupe_findings(self._filter_ignored(findings))

    def scan_history(self) -> list[Finding]:
        """Scan full git history."""
        # Use dual-scanner if ggshield is available
        def gitleaks_scan():
            return self._run_gitleaks(["detect"])

        findings = self._scan_with_both_scanners(gitleaks_scan, ggshield_history=True)
        return self._filter_ignored(findings)

    def scan_smart(self) -> list[Finding]:
        """Smart scan (default mode): staged files + git history only.

        Ignores unstaged changes and untracked/gitignored files — those haven't
        reached version control and pose no leak risk there. Prefer history
        findings in dedup so commit hashes are preserved.
        """
        staged = self.scan_staged()
        history = self.scan_history()
        return self._dedupe_findings(history + staged)

    def scan_all(self, include_untracked: bool = False) -> list[Finding]:
        """Scan both working directory and git history."""
        findings = self.scan_working_directory(include_untracked=include_untracked) + self.scan_history()
        return self._dedupe_findings(findings)

    def _get_gitleaks_config_path(self) -> Path | None:
        """Return path to gitleaks config."""
        repo_config = self.repo_root / ".gitleaks.toml"
        if repo_config.exists():
            return repo_config
        repo_config_yml = self.repo_root / ".gitleaks.yml"
        if repo_config_yml.exists():
            return repo_config_yml
        bundled = Path(__file__).parent / "gitleaks-extended.toml"
        if bundled.exists():
            return bundled
        return None

    def _build_fs_ignore_file(self) -> "tempfile.NamedTemporaryFile":
        """Create a temp gitignore-format file with default system-directory exclusions.

        Returned file must be closed/deleted by the caller.  It is used as
        ``--ignore-path`` when running ``gitleaks detect --no-git`` so that OS
        and toolchain directories (e.g. ``~/.local/``, ``~/.cache/``) are never
        scanned even when the project root happens to be a home directory.
        """
        tf = tempfile.NamedTemporaryFile(
            mode="w", suffix=".leakfixignore", delete=False, prefix="leakfix_"
        )
        tf.write("# Auto-generated by leakfix: system directory exclusions\n")
        for pattern in _DEFAULT_FS_IGNORE_PATTERNS:
            tf.write(pattern + "\n")
        # Also append any .leakfixignore patterns the user has defined so a
        # single --ignore-path flag covers both sets.
        user_patterns = _load_leakfixignore(self.repo_root)
        if user_patterns:
            tf.write("# User .leakfixignore patterns\n")
            for pattern in user_patterns:
                tf.write(pattern + "\n")
        tf.flush()
        tf.close()
        return tf

    def _run_gitleaks(self, args: list[str]) -> list[Finding]:
        """Run gitleaks with given subcommand and args, return parsed findings."""
        if not check_gitleaks_installed():
            raise FileNotFoundError(
                "gitleaks not found. Install with: brew install gitleaks"
            )

        is_no_git_scan = "--no-git" in args

        # For filesystem scans use repo_root (not CWD) so the scan is always
        # bounded to the repository tree, not some parent directory.
        scan_source = self.repo_root if is_no_git_scan else self.source

        cmd = [
            "gitleaks",
            *args,
            "--source",
            str(scan_source),
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--no-banner",
        ]
        config_path = self._get_gitleaks_config_path()
        if config_path is not None:
            cmd.extend(["--config", str(config_path)])

        # For no-git (filesystem) scans inject system-directory exclusions so
        # that OS/tool directories present under a home-rooted repo are skipped.
        ignore_tmp = None
        if is_no_git_scan:
            ignore_tmp = self._build_fs_ignore_file()
            cmd.extend(["--ignore-path", ignore_tmp.name])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(scan_source),
                timeout=300,
            )
            output = result.stdout or result.stderr or ""
            return self._parse_gitleaks_output(output)
        except subprocess.TimeoutExpired:
            return []
        except (subprocess.SubprocessError, FileNotFoundError):
            return []
        finally:
            if ignore_tmp is not None:
                try:
                    Path(ignore_tmp.name).unlink(missing_ok=True)
                except OSError:
                    pass

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
                    match_context=item.get("Match", "").strip(),
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
        """Remove duplicate findings by (file, line, secret_value). Keep highest entropy when collision."""
        by_key: dict[tuple[str, int, str], Finding] = {}
        for f in findings:
            key = (f.file, f.line, f.secret_value)
            if key not in by_key or f.entropy > by_key[key].entropy:
                by_key[key] = f
        return list(by_key.values())

    def _run_ggshield(self, scan_history: bool = False) -> list[Finding]:
        """Run ggshield and return parsed findings."""
        if not check_ggshield_installed():
            return []

        # ggshield secret scan repo scans git history by default
        # For working directory only, use "ggshield secret scan path ."
        if scan_history:
            cmd = ["ggshield", "secret", "scan", "repo", ".", "--json"]
        else:
            cmd = ["ggshield", "secret", "scan", "path", ".", "--json"]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(self.source),
                timeout=600,  # 10 minute timeout for history scans
            )
            output = result.stdout or ""
            return self._parse_ggshield_output(output)
        except subprocess.TimeoutExpired:
            return []
        except (subprocess.SubprocessError, FileNotFoundError):
            return []

    def _parse_ggshield_output(self, json_output: str) -> list[Finding]:
        """Parse ggshield JSON output into Finding objects."""
        findings = []
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            return findings

        # ggshield JSON structure varies by scan type:
        # - repo scan: {"scans": [{"entities_with_incidents": [...], "extra_info": {...}}, ...]}
        # - path scan: {"entities_with_incidents": [...]}
        
        # Collect all entities with their scan context (for commit info)
        scan_entities = []
        
        # Try scans structure first (repo scan)
        scans = data.get("scans", [])
        for scan in scans:
            extra_info = scan.get("extra_info", {})
            commit_sha = scan.get("id", "")  # scan id is the commit sha
            author = extra_info.get("email", "")
            date = extra_info.get("date", "")
            
            for entity in scan.get("entities_with_incidents", []):
                scan_entities.append((entity, commit_sha, author, date))
        
        # Try direct entities_with_incidents (path scan)
        if not scan_entities:
            for entity in data.get("entities_with_incidents", []):
                scan_entities.append((entity, "", "", ""))
        
        # Try results structure (older versions)
        if not scan_entities:
            for entity in data.get("results", []):
                scan_entities.append((entity, "", "", ""))

        for entity, commit_sha, author, date in scan_entities:
            if not isinstance(entity, dict):
                continue

            # Get file info
            file_path = entity.get("filename", entity.get("file", ""))
            if not file_path:
                continue
            file_path = self._normalize_file_path(file_path)

            # Get incidents (secrets found)
            incidents = entity.get("incidents", [])
            for incident in incidents:
                if not isinstance(incident, dict):
                    continue

                # Extract secret info
                secret_type = incident.get("type", incident.get("detector", "unknown"))
                
                # Get match value from occurrences (ggshield masks secrets by default)
                match_value = ""
                line = 0
                occurrences = incident.get("occurrences", [])
                if occurrences and isinstance(occurrences[0], dict):
                    match_value = occurrences[0].get("match", "")
                    line = occurrences[0].get("line_start", occurrences[0].get("line", 0))
                
                # Fallback to incident-level fields
                if not match_value:
                    match_value = incident.get("match", "")
                if not line:
                    line = incident.get("line_start", incident.get("line", 0))

                # Map ggshield severity to our severity levels
                # ggshield doesn't always provide severity, default to high for detected secrets
                gg_severity = incident.get("severity", "high").lower()
                if gg_severity in ("critical", "high"):
                    severity = "high"
                elif gg_severity == "medium":
                    severity = "medium"
                else:
                    severity = "low"

                findings.append(
                    Finding(
                        secret_value=match_value,
                        file=file_path,
                        line=int(line) if line else 0,
                        commit=commit_sha,
                        author=author,
                        date=date,
                        rule_id=secret_type,
                        entropy=0.0,  # ggshield doesn't provide entropy
                        severity=severity,
                        scanner="ggshield",
                    )
                )

        return findings

    def _merge_scanner_findings(
        self, gitleaks_findings: list[Finding], ggshield_findings: list[Finding]
    ) -> list[Finding]:
        """
        Merge findings from both scanners, deduplicating by (file, line, secret_type).
        If both scanners find the same thing, mark it as detected by both.
        """
        # Index gitleaks findings by (file, line, normalized_rule)
        by_key: dict[tuple[str, int, str], Finding] = {}

        def normalize_rule(rule: str) -> str:
            """Normalize rule names for comparison."""
            return rule.lower().replace("-", "_").replace(" ", "_")

        for f in gitleaks_findings:
            key = (f.file, f.line, normalize_rule(f.rule_id))
            by_key[key] = f

        # Merge ggshield findings
        for f in ggshield_findings:
            key = (f.file, f.line, normalize_rule(f.rule_id))
            if key in by_key:
                # Found by both scanners - mark as "both"
                existing = by_key[key]
                by_key[key] = Finding(
                    secret_value=existing.secret_value or f.secret_value,
                    file=existing.file,
                    line=existing.line,
                    commit=existing.commit or f.commit,
                    author=existing.author or f.author,
                    date=existing.date or f.date,
                    rule_id=existing.rule_id,
                    entropy=existing.entropy if existing.entropy else f.entropy,
                    severity=existing.severity if existing.severity != "low" else f.severity,
                    scanner="both",
                )
            else:
                # Only found by ggshield
                by_key[key] = f

        return list(by_key.values())

    def _scan_with_both_scanners(
        self, gitleaks_func, ggshield_history: bool = False
    ) -> list[Finding]:
        """
        Run gitleaks and ggshield in parallel (if ggshield is available).
        Returns merged and deduplicated findings.
        """
        ggshield_available = check_ggshield_installed()

        if not ggshield_available:
            # Fallback to gitleaks only
            return gitleaks_func()

        # Run both scanners in parallel
        gitleaks_findings: list[Finding] = []
        ggshield_findings: list[Finding] = []

        with ThreadPoolExecutor(max_workers=2) as executor:
            future_gitleaks = executor.submit(gitleaks_func)
            future_ggshield = executor.submit(self._run_ggshield, ggshield_history)

            for future in as_completed([future_gitleaks, future_ggshield]):
                if future == future_gitleaks:
                    gitleaks_findings = future.result()
                else:
                    ggshield_findings = future.result()

        # Merge and deduplicate
        return self._merge_scanner_findings(gitleaks_findings, ggshield_findings)
