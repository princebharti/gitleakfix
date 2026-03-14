"""Auto-fix logic - replace secrets in working files and rewrite git history."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from leakfix.classifier import Classification, Classifier
from leakfix.scanner import Finding, Scanner
from leakfix.utils import (
    check_git_filter_repo_installed,
    get_repo_root,
    is_git_repo,
)


def _is_binary_file(file_path: Path) -> bool:
    """Check if a file is binary (contains null bytes or non-UTF-8)."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(8192)
            if b"\x00" in chunk:
                return True
            chunk.decode("utf-8")
        return False
    except (OSError, UnicodeDecodeError):
        return True


def _mask_secret_for_display(secret: str, max_visible: int = 7) -> str:
    """Mask secret for display: first N chars + ***. Never show full value."""
    if len(secret) <= max_visible:
        return secret[:4] + "***" if len(secret) > 4 else "****"
    return secret[:max_visible] + "***"


def _escape_for_replacements(secret: str) -> str:
    """Escape special regex characters for literal matching in git-filter-repo."""
    # git-filter-repo literal: treats the string as literal, but we need to
    # escape any ==> in the secret itself to avoid being parsed as delimiter
    return secret.replace("==>", "\\==>")


class Fixer:
    """Fixes leaked secrets in working files and git history."""

    def __init__(self, source: Path | str | None = None):
        self.source = Path(source or ".").resolve()
        self.repo_root = get_repo_root(self.source) or self.source
        self.scanner = Scanner(self.source)

    def fix_all(
        self,
        dry_run: bool = False,
        replace_with: str = "",
        no_push: bool = False,
        history_only: bool = False,
        files_only: bool = False,
        confirm: bool = False,
        include_review: bool = False,
        llm_enabled: bool = False,
    ) -> tuple[bool, str]:
        """
        Main entry point. Scan, fix working files, rewrite history, commit, push.
        Returns (success, message).
        """
        if not is_git_repo(self.source):
            return False, "Not a git repository"

        if not check_git_filter_repo_installed():
            return False, "git-filter-repo not found. Run: brew install git-filter-repo"

        # Run scan first
        findings = self.scanner.scan_all()
        if not findings:
            return True, "No secrets found"

        # Filter out binary files
        binary_files: set[str] = set()
        text_findings: list[Finding] = []
        for f in findings:
            file_path = self.repo_root / f.file
            if file_path.exists() and _is_binary_file(file_path):
                binary_files.add(f.file)
            else:
                text_findings.append(f)

        if binary_files:
            msg = f"Binary files skipped (manual action needed): {', '.join(sorted(binary_files))}"
            # Continue with text findings

        if not text_findings:
            if binary_files:
                return False, msg
            return True, "No secrets found"

        findings = text_findings

        # Classify and filter: only fix CONFIRMED (and REVIEW_NEEDED if include_review)
        classifier = Classifier(self.repo_root)
        classified = classifier.classify_findings(findings, llm_enabled)
        fixable = [
            c.finding
            for c in classified
            if c.classification == Classification.CONFIRMED
            or (include_review and c.classification == Classification.REVIEW_NEEDED)
        ]
        findings = fixable

        if not findings:
            return True, "No confirmed secrets to fix (all filtered as false positives)"

        # Dedupe by (secret_value, file, line) - same secret on same line = one replacement
        seen: set[tuple[str, str, int]] = set()
        unique_findings: list[Finding] = []
        for f in findings:
            key = (f.secret_value, f.file, f.line)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        findings = unique_findings

        if dry_run:
            false_positives_count = len(
                [c for c in classified if c.classification == Classification.LIKELY_FALSE_POSITIVE]
            )
            return self._dry_run_output(
                findings, replace_with, binary_files, false_positives_count
            )
        if confirm:
            findings = self._confirm_findings(findings, replace_with)
            if not findings:
                return True, "No replacements confirmed"

        # Count commits for summary (before rewrite)
        commit_count = self._count_commits()

        if not history_only:
            self._fix_working_files(findings, replace_with, confirm=False)
            self._commit_changes("chore(security): remove secrets detected by leakfix")

        if not files_only:
            # Save remote URL BEFORE git-filter-repo removes it
            remote, branch = self._get_remote_and_branch()
            remote_url = self._get_remote_url(remote) if remote else None
            replacements_file = self._create_replacements_file(findings, replace_with)
            try:
                self._rewrite_history(replacements_file)
                self._cleanup_reflog()
            finally:
                if replacements_file and replacements_file.exists():
                    replacements_file.unlink()
            # Re-add remote after git-filter-repo removes it
            if remote and remote_url:
                subprocess.run(
                    ["git", "remote", "add", remote, remote_url],
                    cwd=str(self.repo_root),
                    capture_output=True,
                    check=False,
                )

        push_skipped = False
        if not no_push:
            pushed = self._force_push()
            if not pushed:
                push_skipped = True

        file_count = len({f.file for f in findings})
        secret_count = len(findings)

        # Re-verify: use classifier so only CONFIRMED secrets count as failures
        if files_only:
            remaining = self.scanner.scan_working_directory()
        else:
            remaining = self.scanner.scan_all()
        if remaining:
            classified_remaining = classifier.classify_findings(remaining, llm_enabled)
            confirmed = [c for c in classified_remaining if c.classification == Classification.CONFIRMED]
            false_positives = [
                c for c in classified_remaining
                if c.classification == Classification.LIKELY_FALSE_POSITIVE
            ]
            if confirmed:
                return False, f"Verification failed: {len(confirmed)} confirmed secret(s) still present"
            msg = (
                f"✅ 0 confirmed secrets remaining ({len(false_positives)} false positives skipped)\n"
                f"{secret_count} secret(s) removed from {file_count} file(s) across {commit_count} commit(s)"
            )
            if binary_files:
                msg += f"\nBinary files skipped: {', '.join(sorted(binary_files))}"
            if push_skipped:
                msg += "\n⚠️  Push skipped (no remote, protected branch, or push rejected)"
            return True, msg
        summary = f"{secret_count} secret(s) removed from {file_count} file(s) across {commit_count} commit(s)"
        if binary_files:
            summary += f"\nBinary files skipped: {', '.join(sorted(binary_files))}"
        if push_skipped:
            summary += "\n⚠️  Push skipped (no remote, protected branch, or push rejected)"
        return True, summary

    def _dry_run_output(
        self,
        findings: list[Finding],
        replace_with: str,
        binary_files: set[str],
        false_positives_count: int = 0,
    ) -> tuple[bool, str]:
        """Generate dry-run output."""
        lines = ["DRY RUN - No changes will be made", ""]
        lines.append(f"Would replace {len(findings)} secret(s) in {len({f.file for f in findings})} file(s):")
        lines.append("")
        for f in findings:
            display_secret = _mask_secret_for_display(f.secret_value)
            replacement = replace_with if replace_with else "(empty)"
            lines.append(f"  {f.file}:{f.line} - {display_secret} → {replacement}")
        if binary_files:
            lines.append("")
            lines.append(f"Binary files (manual action needed): {', '.join(sorted(binary_files))}")
        if false_positives_count > 0:
            lines.append("")
            lines.append(f"{false_positives_count} false positive(s) skipped (would not be replaced)")
        lines.append("")
        commit_count = self._count_commits()
        lines.append(f"Would rewrite {commit_count} commit(s) in git history")
        remote, branch = self._get_remote_and_branch()
        if remote and branch:
            lines.append(f"Would force push to {remote}/{branch}")
        else:
            lines.append("Would skip push (no remote configured)")
        lines.append("")
        lines.append("Run without --dry-run to apply changes.")
        return True, "\n".join(lines)

    def _confirm_findings(
        self,
        findings: list[Finding],
        replace_with: str,
    ) -> list[Finding]:
        """Ask user to confirm each replacement. Returns only confirmed findings."""
        from rich.console import Console
        from rich.prompt import Confirm

        console = Console()
        confirmed = []
        for f in findings:
            display_secret = _mask_secret_for_display(f.secret_value)
            replacement = replace_with if replace_with else "(empty)"
            if Confirm.ask(
                f"Replace in {f.file}:{f.line} - {display_secret} → {replacement}?",
                default=True,
            ):
                confirmed.append(f)
        return confirmed

    def _fix_working_files(
        self,
        findings: list[Finding],
        replace_with: str,
        confirm: bool = False,
    ) -> None:
        """Replace secrets in current working files."""
        # Group by file
        by_file: dict[str, list[Finding]] = {}
        for f in findings:
            by_file.setdefault(f.file, []).append(f)

        for file_path_str, file_findings in by_file.items():
            full_path = self.repo_root / file_path_str
            if not full_path.exists() or _is_binary_file(full_path):
                continue
            try:
                content = full_path.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue
            lines = content.splitlines(keepends=True)
            # Sort by line descending so we don't mess up indices
            for f in sorted(file_findings, key=lambda x: -x.line):
                line_idx = f.line - 1
                if 0 <= line_idx < len(lines):
                    old_line = lines[line_idx]
                    # Replace all occurrences of the secret on this line
                    new_line = old_line.replace(f.secret_value, replace_with)
                    if new_line != old_line:
                        lines[line_idx] = new_line
            full_path.write_text("".join(lines))

        # Stage changed files
        for file_path_str in by_file:
            full_path = self.repo_root / file_path_str
            if full_path.exists():
                subprocess.run(
                    ["git", "add", str(full_path)],
                    cwd=str(self.repo_root),
                    capture_output=True,
                    check=False,
                )

    def _create_replacements_file(
        self,
        findings: list[Finding],
        replace_with: str,
    ) -> Path | None:
        """Create replacements.txt for git-filter-repo. Format: literal:secret==>replacement"""
        # Dedupe by secret value - same secret gets one replacement rule
        secrets_seen: set[str] = set()
        replacements: list[str] = []
        for f in findings:
            if f.secret_value not in secrets_seen:
                secrets_seen.add(f.secret_value)
                escaped = _escape_for_replacements(f.secret_value)
                replacements.append(f"literal:{escaped}==>{replace_with}")
        if not replacements:
            return None
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="leakfix-replacements-")
        try:
            with open(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(replacements) + "\n")
            return Path(path)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            if Path(path).exists():
                Path(path).unlink()
            raise

    def _rewrite_history(self, replacements_file: Path | None) -> None:
        """Run git-filter-repo to rewrite history."""
        if not replacements_file or not replacements_file.exists():
            return
        subprocess.run(
            ["git-filter-repo", "--replace-text", str(replacements_file), "--force"],
            cwd=str(self.repo_root),
            check=True,
        )

    def _commit_changes(self, message: str) -> None:
        """Commit the working directory changes."""
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
        )
        if not result.stdout.strip():
            return
        subprocess.run(
            ["git", "add", "-A"],
            cwd=str(self.repo_root),
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-m", message],
            cwd=str(self.repo_root),
            capture_output=True,
            check=False,
        )

    def _force_push(self) -> bool:
        """Force push to remote. Returns True if pushed, False if skipped."""
        remote, branch = self._get_remote_and_branch()
        if not remote or not branch:
            return False
        try:
            subprocess.run(
                ["git", "push", "--force", remote, branch],
                cwd=str(self.repo_root),
                capture_output=True,
                text=True,
                check=True,
            )
            return True
        except subprocess.CalledProcessError as e:
            if "protected" in (e.stderr or "").lower() or "rejected" in (e.stderr or "").lower():
                return False
            raise

    def _cleanup_reflog(self) -> None:
        """Run git reflog expire + git gc."""
        subprocess.run(
            ["git", "reflog", "expire", "--expire=now", "--all"],
            cwd=str(self.repo_root),
            capture_output=True,
            check=False,
        )
        subprocess.run(
            ["git", "gc", "--prune=now"],
            cwd=str(self.repo_root),
            capture_output=True,
            check=False,
        )

    def _verify_clean(self) -> list[Finding]:
        """Run final scan to verify no secrets remain."""
        return self.scanner.scan_all()

    def _count_commits(self) -> int:
        """Count commits in the repository."""
        result = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip().isdigit():
            return int(result.stdout.strip())
        return 0

    def _get_remote_url(self, remote: str | None) -> str | None:
        """Get the URL of a remote."""
        if not remote:
            return None
        result = subprocess.run(
            ["git", "remote", "get-url", remote],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
        )
        return result.stdout.strip() if result.returncode == 0 else None

    def _get_remote_and_branch(self) -> tuple[str | None, str | None]:
        """Get remote name and current branch."""
        branch_result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
        )
        branch = branch_result.stdout.strip() if branch_result.returncode == 0 else None
        if not branch or branch == "HEAD":
            return None, None
        remote_result = subprocess.run(
            ["git", "config", f"branch.{branch}.remote"],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
        )
        remote = remote_result.stdout.strip() if remote_result.returncode == 0 else None
        if not remote:
            remote = "origin"
            # Check if origin exists
            remotes = subprocess.run(
                ["git", "remote"],
                cwd=str(self.repo_root),
                capture_output=True,
                text=True,
            )
            if "origin" not in (remotes.stdout or "").split():
                return None, branch
        return remote, branch
