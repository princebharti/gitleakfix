"""Auto-fix logic - replace secrets in working files and rewrite git history."""

from __future__ import annotations

import json
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

# Module-level cache for the fix prompt
_FIX_PROMPT_CACHE: str | None = None

# Fallback prompt if file not found
_FALLBACK_FIX_PROMPT = """You are a security engineer. Replace this secret with a safe value.
Secret: "{secret_value}"
File: {file_path}
Line {line_number}:
{context_lines}

Return JSON only: {"replacement": "<value>", "reason": "<why>", "confident": true/false}"""


def _load_fix_prompt() -> str:
    """
    Load the fix prompt from leakfix/prompts/fix_secret.txt.
    Falls back to a hardcoded minimal prompt if file not found.
    Cached at module level after first load.
    """
    global _FIX_PROMPT_CACHE
    if _FIX_PROMPT_CACHE is not None:
        return _FIX_PROMPT_CACHE

    # Try to load from package directory
    prompt_path = Path(__file__).parent / "prompts" / "fix_secret.txt"
    try:
        if prompt_path.exists():
            _FIX_PROMPT_CACHE = prompt_path.read_text(encoding="utf-8")
            return _FIX_PROMPT_CACHE
    except (OSError, UnicodeDecodeError):
        pass

    # Fallback to hardcoded minimal prompt
    _FIX_PROMPT_CACHE = _FALLBACK_FIX_PROMPT
    return _FIX_PROMPT_CACHE


def _get_llm_config() -> dict | None:
    """Load LLM config from ~/.leakfix/config.json. Returns None if disabled or not found."""
    config_path = Path.home() / ".leakfix" / "config.json"
    try:
        if config_path.exists():
            config = json.loads(config_path.read_text(encoding="utf-8"))
            if config.get("llm_enabled", False):
                return config
    except (OSError, json.JSONDecodeError):
        pass
    return None


def _get_context_lines(
    file_path: Path,
    line_number: int,
    context: int = 5,
    secret_value: str = "",
    repo_root: Path | None = None,
) -> str:
    """
    Read context lines around the secret line from the actual file.
    Returns lines (line_number - context) to (line_number + context).
    
    If the secret is not found in the current file (history-only finding),
    attempts to retrieve context from git history.
    """
    content = None
    
    # First try to read from the current file
    try:
        if file_path.exists():
            content = file_path.read_text(encoding="utf-8", errors="replace")
            # Check if the secret is actually in this file
            if secret_value and secret_value not in content:
                content = None  # Secret not in current file, try git history
    except (OSError, UnicodeDecodeError):
        pass
    
    # If secret not in current file, try git history
    if content is None and repo_root and secret_value:
        try:
            # Get the relative path for git
            try:
                rel_path = file_path.relative_to(repo_root)
            except ValueError:
                rel_path = file_path
            
            # Find the commit that contains this secret
            result = subprocess.run(
                ["git", "log", "--all", "-p", "-S", secret_value, "--", str(rel_path)],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout:
                # Extract the file content from the diff
                # Find the commit hash first
                import re
                commit_match = re.search(r"^commit ([a-f0-9]+)", result.stdout, re.MULTILINE)
                if commit_match:
                    commit_hash = commit_match.group(1)
                    # Get the file content at that commit
                    show_result = subprocess.run(
                        ["git", "show", f"{commit_hash}:{rel_path}"],
                        cwd=str(repo_root),
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if show_result.returncode == 0:
                        content = show_result.stdout
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
    
    if not content:
        return ""
    
    try:
        lines = content.splitlines()
        
        # If we got content from git history, we need to find the actual line number
        # since it might differ from what the scanner reported
        if secret_value:
            for i, line in enumerate(lines):
                if secret_value in line:
                    line_number = i + 1
                    break
        
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        context_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_number - 1 else "    "
            context_lines.append(f"{prefix}{i + 1}: {lines[i]}")
        return "\n".join(context_lines)
    except Exception:
        return ""


def _intelligent_replacement(
    secret_value: str,
    file_path: str,
    line_number: int,
    rule_id: str,
    repo_root: Path,
) -> tuple[str, str | None, bool]:
    """
    Use LLM to generate an intelligent replacement for a secret.
    
    Returns:
        tuple of (replacement_value, reason, used_llm)
        - replacement_value: the string to replace the secret with
        - reason: explanation from LLM (None if fallback used)
        - used_llm: True if LLM was used successfully, False if fallback
    """
    # Check if LLM is enabled
    config = _get_llm_config()
    if not config:
        return _safe_replacement(rule_id), None, False

    # Get file extension
    full_path = repo_root / file_path
    extension = full_path.suffix.lstrip(".") if full_path.suffix else "unknown"

    # Get context lines from the actual file (or git history for history-only findings)
    context_lines = _get_context_lines(
        full_path, line_number, context=5, secret_value=secret_value, repo_root=repo_root
    )
    if not context_lines:
        return _safe_replacement(rule_id), None, False

    # Load and format the prompt using safe string replacement
    # (can't use .format() because context_lines may contain {VAR:-value} patterns)
    prompt_template = _load_fix_prompt()
    prompt = prompt_template.replace("{file_path}", file_path)
    prompt = prompt.replace("{extension}", extension)
    prompt = prompt.replace("{secret_value}", secret_value)
    prompt = prompt.replace("{line_number}", str(line_number))
    prompt = prompt.replace("{context_lines}", context_lines)

    # Call Ollama with timeout
    try:
        import ollama
        
        model = config.get("llm_model", "qwen3-coder:30b")
        base_url = config.get("llm_base_url", "http://localhost:11434")
        
        # Create client with base URL
        client = ollama.Client(host=base_url)
        
        # Call with timeout (ollama client doesn't have native timeout, use subprocess fallback)
        import threading
        result_container: dict = {}
        error_container: dict = {}
        
        def call_llm():
            try:
                response = client.chat(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    options={"temperature": 0.1},
                )
                result_container["response"] = response
            except Exception as e:
                error_container["error"] = e
        
        thread = threading.Thread(target=call_llm)
        thread.start()
        thread.join(timeout=10.0)  # 10 second timeout
        
        if thread.is_alive():
            # Timeout - fall back to safe replacement
            return _safe_replacement(rule_id), None, False
        
        if "error" in error_container:
            return _safe_replacement(rule_id), None, False
        
        if "response" not in result_container:
            return _safe_replacement(rule_id), None, False
        
        response = result_container["response"]
        response_text = response.get("message", {}).get("content", "")
        
        # Parse JSON response
        # Handle potential markdown code blocks
        response_text = response_text.strip()
        if response_text.startswith("```"):
            # Remove markdown code block
            lines = response_text.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            response_text = "\n".join(lines)
        
        # Parse JSON
        try:
            result = json.loads(response_text)
        except json.JSONDecodeError:
            return _safe_replacement(rule_id), None, False
        
        # Validate response structure
        if not isinstance(result, dict):
            return _safe_replacement(rule_id), None, False
        
        replacement = result.get("replacement")
        reason = result.get("reason")
        confident = result.get("confident", False)
        
        # Validation checks
        if replacement is None:
            return _safe_replacement(rule_id), None, False
        
        # Must be a string
        if not isinstance(replacement, str):
            return _safe_replacement(rule_id), None, False
        
        # Must not contain the original secret
        if secret_value in replacement:
            return _safe_replacement(rule_id), None, False
        
        # Must be a single line
        if "\n" in replacement:
            return _safe_replacement(rule_id), None, False
        
        # If not confident, fall back
        if not confident:
            return _safe_replacement(rule_id), reason, False
        
        return replacement, reason, True
        
    except ImportError:
        return _safe_replacement(rule_id), None, False
    except Exception:
        return _safe_replacement(rule_id), None, False


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
    """
    Escape special characters for git-filter-repo replacements file.
    Format: literal:SECRET==>REPLACEMENT
    Special chars that need handling:
    - ==> : the delimiter itself
    - newlines : would break the line-per-rule format
    - null bytes : would corrupt the file
    """
    # Escape the delimiter first
    result = secret.replace("==>", "\\==>")
    # Replace newlines with space (git-filter-repo treats each line as one rule)
    result = result.replace("\n", " ").replace("\r", "")
    # Replace null bytes
    result = result.replace("\x00", "")
    return result


def _safe_replacement(rule_id: str) -> str:
    """
    Return a replacement string that:
    - Has very low entropy (all same chars or obvious pattern)
    - Is clearly a placeholder — won't be flagged by any scanner
    - Is contextually appropriate for the secret type
    - Never empty (empty values still suspicious on variable lines)
    """
    rule_lower = rule_id.lower()
    if "aws" in rule_lower:
        return "AKIAIOSFODNN7EXAMPLE"
    if "github" in rule_lower or "ghp" in rule_lower:
        return "ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    if "gitlab" in rule_lower:
        return "glpat-xxxxxxxxxxxxxxxxxxxx"
    if "slack" in rule_lower:
        return "xoxb-REDACTED"
    if "stripe" in rule_lower:
        return "sk_test_REDACTED"
    if "twilio" in rule_lower:
        return "SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    if "sendgrid" in rule_lower:
        return "SG-REDACTED"
    if "openai" in rule_lower or "sk-" in rule_lower:
        return "sk-REDACTED"
    if "private-key" in rule_lower or "pem" in rule_lower:
        return "-----BEGIN PRIVATE KEY-----\nREDACTED_BY_LEAKFIX\n-----END PRIVATE KEY-----"
    return "REDACTED"


class Fixer:
    """Fixes leaked secrets in working files and git history."""

    def __init__(self, source: Path | str | None = None):
        self.source = Path(source or ".").resolve()
        self.repo_root = get_repo_root(self.source) or self.source
        self.scanner = Scanner(self.source)
        self._skipped_untracked_files: set[str] = set()

    def _is_git_tracked(self, file_path: str) -> bool:
        """Return True if file is tracked by git."""
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch", file_path],
            cwd=str(self.repo_root),
            capture_output=True,
            check=False,
        )
        return result.returncode == 0

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
        include_untracked: bool = False,
        fix_all_findings: bool = False,
    ) -> tuple[bool, str]:
        """
        Main entry point. Scan, fix working files, rewrite history, commit, push.
        Returns (success, message).
        """
        if not is_git_repo(self.source):
            return False, "Not a git repository"

        if not check_git_filter_repo_installed():
            return False, "git-filter-repo not found. Run: brew install git-filter-repo"

        # Run scan first - use include_untracked for working directory scan
        working_findings = self.scanner.scan_working_directory(include_untracked=include_untracked)
        history_findings = self.scanner.scan_history()
        findings = self.scanner._dedupe_findings(working_findings + history_findings)
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

        # When fix_all_findings is True, skip classification and fix everything
        classifier = Classifier(self.repo_root)  # always init for re-verify step later
        if fix_all_findings:
            # Fix all findings regardless of classification
            pass  # findings = text_findings (already set)
        else:
            # Classify and filter: only fix CONFIRMED (and REVIEW_NEEDED if include_review)
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
            if fix_all_findings:
                false_positives_count = 0  # Not applicable in fix-all mode
            else:
                false_positives_count = len(
                    [c for c in classified if c.classification == Classification.LIKELY_FALSE_POSITIVE]
                )
            return self._dry_run_output(
                findings, replace_with, binary_files, false_positives_count, fix_all_findings
            )
        if confirm:
            findings = self._confirm_findings(findings, replace_with)
            if not findings:
                return True, "No replacements confirmed"

        # Count commits for summary (before rewrite)
        commit_count = self._count_commits()

        # Pre-compute intelligent replacements for all findings
        # Key: (secret_value, file, line) -> (replacement, reason, used_llm)
        replacement_map: dict[tuple[str, str, int], tuple[str, str | None, bool]] = {}
        fix_logs: list[str] = []
        
        from rich.console import Console
        console = Console()
        
        for f in findings:
            key = (f.secret_value, f.file, f.line)
            if key not in replacement_map:
                if replace_with:
                    # User specified explicit replacement
                    replacement_map[key] = (replace_with, None, False)
                else:
                    # Use intelligent replacement
                    replacement, reason, used_llm = _intelligent_replacement(
                        f.secret_value, f.file, f.line, f.rule_id, self.repo_root
                    )
                    replacement_map[key] = (replacement, reason, used_llm)
                    
                    # Log which method was used
                    display_secret = _mask_secret_for_display(f.secret_value)
                    if used_llm and reason:
                        fix_logs.append(f"✓ Fixed intelligently: \"{display_secret}\" → \"{replacement}\" ({reason})")
                    else:
                        fix_logs.append(f"✓ Fixed with placeholder: \"{display_secret}\" → \"{replacement}\"")

        # Print fix logs
        for log in fix_logs:
            console.print(log)

        # BUG A FIX: Split findings into two separate lists BEFORE processing
        # Findings to write to disk — only tracked files (or all if include_untracked)
        tracked = self.scanner.get_tracked_files()
        disk_findings = [
            f for f in findings
            if include_untracked or f.file in tracked
        ]

        # Findings for history rewrite — ALL findings regardless of tracking status
        # A file may be untracked now but WAS in history — must still clean history
        history_findings = findings  # no filter

        if not history_only:
            self._fix_working_files(disk_findings, replace_with, confirm=False, include_untracked=include_untracked, replacement_map=replacement_map)
            self._commit_changes("chore(security): remove secrets detected by leakfix")

        # Build skipped warnings for untracked files
        all_skipped = self.scanner._untracked_files_warned | self._skipped_untracked_files
        skipped_warnings = ""
        if all_skipped:
            skipped_lines = [
                f"⚠️  Skipped {f} (not tracked by git — safe to keep secrets here)"
                for f in sorted(all_skipped)
            ]
            skipped_warnings = "\n" + "\n".join(skipped_lines)

        if not files_only:
            # Warn about potentially protected branches before history rewrite
            if not no_push:
                protected = self._detect_protected_branches()
                if protected:
                    self._warn_protected_branches(protected, console)
            
            # Save remote URL BEFORE git-filter-repo removes it
            remote, branch = self._get_remote_and_branch()
            remote_url = self._get_remote_url(remote) if remote else None
            # Use history_findings (all findings) for history rewrite, not just disk_findings
            replacements_file = self._create_replacements_file(history_findings, replace_with, replacement_map=replacement_map)
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

        push_summary = ""
        if not no_push:
            push_results = self._force_push_all_branches()
            push_summary = self._format_push_summary(push_results)

        file_count = len({f.file for f in findings})
        secret_count = len(findings)

        # Re-verify with gitleaks-only for speed and deterministic local behavior.
        # Running ggshield history scans here can add long delays after rewrite.
        # When fix_all_findings=True, ANY remaining secret is a failure.
        if files_only:
            remaining = self._verify_with_gitleaks_only(include_untracked=include_untracked, files_only=True)
        else:
            remaining = self._verify_with_gitleaks_only(include_untracked=include_untracked, files_only=False)
        if remaining:
            if fix_all_findings:
                # In --all mode, any remaining secret is a failure (no classification filtering)
                return False, f"Verification failed: {len(remaining)} secret(s) still present{skipped_warnings}"
            classified_remaining = classifier.classify_findings(remaining, llm_enabled)
            confirmed = [c for c in classified_remaining if c.classification == Classification.CONFIRMED]
            false_positives = [
                c for c in classified_remaining
                if c.classification == Classification.LIKELY_FALSE_POSITIVE
            ]
            if confirmed:
                return False, f"Verification failed: {len(confirmed)} confirmed secret(s) still present{skipped_warnings}"
            msg = (
                f"✅ 0 confirmed secrets remaining ({len(false_positives)} false positives skipped)\n"
                f"{secret_count} secret(s) removed from {file_count} file(s) across {commit_count} commit(s)"
            )
            if binary_files:
                msg += f"\nBinary files skipped: {', '.join(sorted(binary_files))}"
            if push_summary:
                msg += f"\n{push_summary}"
            msg += skipped_warnings
            return True, msg
        summary = f"{secret_count} secret(s) removed from {file_count} file(s) across {commit_count} commit(s)"
        if binary_files:
            summary += f"\nBinary files skipped: {', '.join(sorted(binary_files))}"
        if push_summary:
            summary += f"\n{push_summary}"
        summary += skipped_warnings
        return True, summary

    def _verify_with_gitleaks_only(
        self,
        include_untracked: bool = False,
        files_only: bool = False,
    ) -> list[Finding]:
        """
        Fast post-fix verification path using gitleaks only.
        This avoids an extra full ggshield repo scan that can look like a hang.
        """
        working = self.scanner._run_gitleaks(["detect", "--no-git"])
        working = self.scanner._filter_ignored(working)
        working = self.scanner._dedupe_findings(working)

        if not include_untracked:
            tracked = self.scanner.get_tracked_files()
            if tracked:
                working = [f for f in working if f.file in tracked]

        if files_only:
            return working

        history = self.scanner._run_gitleaks(["detect"])
        history = self.scanner._filter_ignored(history)
        return self.scanner._dedupe_findings(working + history)

    def _dry_run_output(
        self,
        findings: list[Finding],
        replace_with: str,
        binary_files: set[str],
        false_positives_count: int = 0,
        fix_all_mode: bool = False,
    ) -> tuple[bool, str]:
        """Generate dry-run output."""
        lines = ["DRY RUN - No changes will be made", ""]
        if fix_all_mode:
            lines.insert(1, "⚠️  Fix-all mode: removing all findings including false positives")
            lines.insert(2, "")
        lines.append(f"Would replace {len(findings)} secret(s) in {len({f.file for f in findings})} file(s):")
        lines.append("")
        for f in findings:
            display_secret = _mask_secret_for_display(f.secret_value)
            if replace_with:
                replacement = replace_with
                method = ""
            else:
                replacement, reason, used_llm = _intelligent_replacement(
                    f.secret_value, f.file, f.line, f.rule_id, self.repo_root
                )
                method = " (intelligent)" if used_llm else " (placeholder)"
            lines.append(f"  {f.file}:{f.line} - {display_secret} → {replacement}{method}")
        if binary_files:
            lines.append("")
            lines.append(f"Binary files (manual action needed): {', '.join(sorted(binary_files))}")
        if false_positives_count > 0:
            lines.append("")
            lines.append(f"{false_positives_count} false positive(s) skipped (would not be replaced)")
        lines.append("")
        commit_count = self._count_commits()
        lines.append(f"Would rewrite {commit_count} commit(s) in git history")
        
        # Show all branches that would be pushed
        branches = self._get_all_local_branches()
        remotes_result = subprocess.run(
            ["git", "remote"],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
        )
        remotes = [r.strip() for r in (remotes_result.stdout or "").split() if r.strip()]
        
        if remotes and branches:
            remote = "origin" if "origin" in remotes else remotes[0]
            lines.append(f"Would force push {len(branches)} branch(es) to {remote}:")
            for branch in branches:
                lines.append(f"  - {branch}")
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
            replacement = replace_with if replace_with else _safe_replacement(f.rule_id)
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
        include_untracked: bool = False,
        replacement_map: dict[tuple[str, str, int], tuple[str, str | None, bool]] | None = None,
    ) -> None:
        """Replace secrets in current working files."""
        # Group by file
        by_file: dict[str, list[Finding]] = {}
        for f in findings:
            by_file.setdefault(f.file, []).append(f)

        # Pre-compute tracked files set (one git call instead of N)
        tracked: set[str] = set()
        if not include_untracked:
            tracked = self.scanner.get_tracked_files()

        for file_path_str, file_findings in by_file.items():
            # Skip untracked files unless include_untracked is True
            if not include_untracked and file_path_str not in tracked:
                self._skipped_untracked_files.add(file_path_str)
                continue

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
                    # Determine replacement: use pre-computed intelligent replacement if available
                    key = (f.secret_value, f.file, f.line)
                    if replacement_map and key in replacement_map:
                        actual_replacement = replacement_map[key][0]
                    elif replace_with:
                        actual_replacement = replace_with
                    else:
                        actual_replacement = _safe_replacement(f.rule_id)
                    new_line = old_line.replace(f.secret_value, actual_replacement)
                    if new_line != old_line:
                        lines[line_idx] = new_line
            full_path.write_text("".join(lines))

        # Stage changed files (only tracked ones)
        for file_path_str in by_file:
            if file_path_str in self._skipped_untracked_files:
                continue
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
        replacement_map: dict[tuple[str, str, int], tuple[str, str | None, bool]] | None = None,
    ) -> Path | None:
        """Create replacements.txt for git-filter-repo. Format: literal:secret==>replacement"""
        # Dedupe by secret_value - same secret value gets one replacement
        # git-filter-repo replaces ALL occurrences of the secret value in history
        secrets_seen: set[str] = set()
        replacements: list[str] = []
        for f in findings:
            if f.secret_value not in secrets_seen:
                secrets_seen.add(f.secret_value)
                escaped = _escape_for_replacements(f.secret_value)
                # Skip unparseable secret values (empty or whitespace after escaping)
                if not escaped.strip():
                    continue
                # Determine replacement: use pre-computed intelligent replacement if available
                key = (f.secret_value, f.file, f.line)
                if replacement_map and key in replacement_map:
                    actual_replacement = replacement_map[key][0]
                elif replace_with:
                    actual_replacement = replace_with
                else:
                    actual_replacement = _safe_replacement(f.rule_id)
                replacements.append(f"literal:{escaped}==>{actual_replacement}")
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
            ["git", "add", "-u"],
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

    def _get_all_local_branches(self) -> list[str]:
        """Get all local branch names."""
        result = subprocess.run(
            ["git", "branch", "--format=%(refname:short)"],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return []
        return [b.strip() for b in result.stdout.strip().split("\n") if b.strip()]

    def _detect_protected_branches(self) -> list[str]:
        """
        Detect branches that are likely protected on the remote.
        Returns list of branch names that may be protected.
        
        Note: We can't definitively detect protected branches without API access,
        but we can warn about common protected branch patterns.
        """
        # Common protected branch names
        protected_patterns = {"main", "master", "develop", "release", "production", "prod"}
        
        # Get remote branches
        result = subprocess.run(
            ["git", "branch", "-r", "--format=%(refname:short)"],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return []
        
        remote_branches = [b.strip() for b in result.stdout.strip().split("\n") if b.strip()]
        
        # Check which local branches have remote counterparts that might be protected
        local_branches = self._get_all_local_branches()
        potentially_protected = []
        
        for local in local_branches:
            # Check if this branch name matches a protected pattern
            if local.lower() in protected_patterns:
                # Check if it has a remote counterpart
                for remote in remote_branches:
                    # remote format is "origin/branch" or "upstream/branch"
                    if remote.endswith(f"/{local}"):
                        potentially_protected.append(local)
                        break
        
        return potentially_protected

    def _warn_protected_branches(self, branches: list[str], console) -> bool:
        """
        Warn user about potentially protected branches before history rewrite.
        Returns True if user should proceed, False if they should abort.
        """
        if not branches:
            return True
        
        console.print()
        console.print("[bold yellow]⚠️  WARNING: Potentially protected branches detected[/bold yellow]")
        console.print()
        console.print("The following branches may be protected on your remote:")
        for branch in branches:
            console.print(f"  • {branch}")
        console.print()
        console.print("[bold]Before proceeding, you may need to:[/bold]")
        console.print()
        console.print("[bold]GitLab:[/bold]")
        console.print("  1. Go to Settings → Repository → Protected branches")
        console.print("  2. Unprotect the branches listed above")
        console.print("  3. Re-protect them after the push completes")
        console.print()
        console.print("[bold]GitHub:[/bold]")
        console.print("  1. Go to Settings → Branches → Branch protection rules")
        console.print("  2. Temporarily disable 'Allow force pushes' restriction")
        console.print("  3. Or delete the protection rule and recreate after push")
        console.print()
        console.print("[dim]If push fails with 'protected branch' error, follow the steps above.[/dim]")
        console.print()
        
        return True  # Continue with the operation

    def _force_push_all_branches(self) -> dict[str, str]:
        """
        Force push all local branches to remote after history rewrite.
        Returns dict mapping branch name to status:
          - "pushed": successfully pushed
          - "protected": branch is protected, push rejected
          - "no_remote": no remote configured
          - "error": other error occurred
        """
        branches = self._get_all_local_branches()
        if not branches:
            return {}

        # Check if any remote exists
        remotes_result = subprocess.run(
            ["git", "remote"],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
        )
        remotes = [r.strip() for r in (remotes_result.stdout or "").split() if r.strip()]
        if not remotes:
            return {b: "no_remote" for b in branches}

        remote = "origin" if "origin" in remotes else remotes[0]
        results: dict[str, str] = {}

        for branch in branches:
            try:
                push_result = subprocess.run(
                    [
                        "git", "push", "--force", remote, branch,
                        "-o", "secret_push_protection.skip_all"
                    ],
                    cwd=str(self.repo_root),
                    capture_output=True,
                    text=True,
                    check=True,
                )
                results[branch] = "pushed"
            except subprocess.CalledProcessError as e:
                stderr = (e.stderr or "").lower()
                if "protected" in stderr or "rejected" in stderr:
                    results[branch] = "protected"
                elif "no such remote" in stderr or "does not appear to be a git repository" in stderr:
                    results[branch] = "no_remote"
                else:
                    results[branch] = "error"

        return results

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

    def _format_push_summary(self, push_results: dict[str, str]) -> str:
        """Format the push results into a human-readable summary."""
        if not push_results:
            return ""

        lines: list[str] = []
        pushed = [b for b, s in push_results.items() if s == "pushed"]
        protected = [b for b, s in push_results.items() if s == "protected"]
        no_remote = [b for b, s in push_results.items() if s == "no_remote"]
        errors = [b for b, s in push_results.items() if s == "error"]

        # Show individual branch results
        for branch in pushed:
            lines.append(f"✓  Force pushed cleaned history to {branch}")

        for branch in protected:
            lines.append(f"⚠️  Could not push {branch} (protected) — unprotect in GitLab/GitHub settings and re-run")

        if no_remote:
            lines.append("⚠️  No remote configured — run: git remote add origin <url>")

        for branch in errors:
            lines.append(f"⚠️  Failed to push {branch} (unknown error)")

        # Add summary line
        if lines:
            lines.append("")
            summary_parts = []
            if pushed:
                summary_parts.append(f"{len(pushed)} pushed")
            if protected or no_remote or errors:
                skipped_count = len(protected) + len(no_remote) + len(errors)
                summary_parts.append(f"{skipped_count} skipped")
            lines.append(f"Push summary: {', '.join(summary_parts)}")

        return "\n".join(lines)

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
