"""False positive classifier - filters placeholder and example secrets from real leaks."""

from __future__ import annotations

import logging
import math
import re
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from leakfix.scanner import Finding

# Log to ~/.leakfix/leakfix.log when ollama is unavailable
_LEAKFIX_HOME = Path.home() / ".leakfix"
_LEAKFIX_LOG = _LEAKFIX_HOME / "leakfix.log"
_logger: logging.Logger | None = None
_logger_lock = threading.Lock()


def _get_logger() -> logging.Logger:
    """Get or create logger for leakfix. Thread-safe with double-checked locking."""
    global _logger
    if _logger is None:
        with _logger_lock:
            if _logger is None:
                _logger = logging.getLogger("leakfix")
                _logger.setLevel(logging.INFO)
                if not _logger.handlers:
                    _LEAKFIX_HOME.mkdir(parents=True, exist_ok=True)
                    h = logging.FileHandler(_LEAKFIX_LOG, encoding="utf-8")
                    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
                    _logger.addHandler(h)
    return _logger


class Classification(Enum):
    """Classification result for a secret finding."""

    CONFIRMED = "confirmed"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    REVIEW_NEEDED = "review_needed"


@dataclass
class ClassifiedFinding:
    """A finding with its classification and reason."""

    finding: Finding
    classification: Classification
    reason: str


# Placeholder substrings (case-insensitive)
# Note: "1234" and "0000" are handled specially in _check_placeholder_patterns
PLACEHOLDER_PATTERNS = [
    "your-",
    "xxx",
    "placeholder",
    "changeme",
    "dummy",
    "replace-me",
    "todo",
    "insert-here",
    "your_token",
    "your_key",
    "your_secret",
]

# Known placeholder patterns for specific tools (exact or regex)
TOOL_PLACEHOLDER_PATTERNS = [
    (r"^glpat-your-gitlab-personal-access-token$", "GitLab placeholder token"),
    (r"^ghp_x{32,}$", "GitHub PAT placeholder (all x)"),
    (r"^sk-x{32,}$", "OpenAI API key placeholder (all x)"),
    (r"^AKIA\*{16}$", "AWS key placeholder (all asterisks)"),
]

# File extensions/suffixes that indicate example/template files
FILE_PLACEHOLDER_SUFFIXES = (".example", ".sample", ".template", ".placeholder")

# Directory path segments that indicate test/example code
TEST_DIR_PATTERNS = ("/test", "/spec", "/mock", "/fixture", "/stub")

# Extended path segments that indicate example/template files
TEMPLATE_PATH_SEGMENTS = (
    ".example", ".sample", ".template",
    "/example", "/examples", "/sample", "/samples",
    "/template", "/templates", "/docs", "/doc",
    "readme", "contributing", "changelog",
    "/fixtures", "/fixture", "/mocks", "/mock",
    "/stubs", "/stub", "/seeds", "/seed",
)

# Entropy threshold below which we consider low entropy
ENTROPY_THRESHOLD = 3.0

# High-confidence rules where _check_value_is_word_like should be bypassed
HIGH_CONFIDENCE_RULES = {
    "aws-access-key", "aws-secret-key", "github-pat", "gitlab-pat",
    "slack-token", "private-key", "private-key-pem", "openssh-private-key",
    "generic-sk-secret-key",
}


def _compute_entropy(value: str) -> float:
    """Compute Shannon entropy of a string (bits per character)."""
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for c in value:
        freq[c] = freq.get(c, 0) + 1
    n = len(value)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _mask_for_display(secret: str, max_visible: int = 7) -> str:
    """Mask secret for display: first N chars + ***."""
    if len(secret) <= max_visible:
        return secret[:4] + "***" if len(secret) > 4 else "****"
    return secret[:max_visible] + "***"


class Classifier:
    """Classifies secret findings as CONFIRMED, LIKELY_FALSE_POSITIVE, or REVIEW_NEEDED."""

    def __init__(self, repo_root: Path | str | None = None):
        self.repo_root = Path(repo_root or ".").resolve()

    def _load_context_lines(self, finding: Finding, window: int = 15) -> str:
        """
        Load ±window lines around the finding's line number.
        Returns a formatted string with line numbers and a marker for the secret line.
        Returns empty string if file unreadable or not on disk.
        """
        full_path = self.repo_root / finding.file
        if not full_path.exists():
            return ""
        try:
            lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except (OSError, UnicodeDecodeError):
            return ""

        line_idx = finding.line - 1
        start = max(0, line_idx - window)
        end = min(len(lines), line_idx + window + 1)

        context_lines = []
        for i in range(start, end):
            marker = "  ← SECRET ON THIS LINE" if i == line_idx else ""
            context_lines.append(f"  {i+1:4d}: {lines[i]}{marker}")
        return "\n".join(context_lines)

    def _load_file_header(self, finding: Finding, n: int = 5) -> str:
        """Load first N lines of the file for top-level context (license, docstrings, comments)."""
        full_path = self.repo_root / finding.file
        if not full_path.exists():
            return ""
        try:
            lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()[:n]
            return "\n".join(f"  {i+1}: {l}" for i, l in enumerate(lines))
        except (OSError, UnicodeDecodeError):
            return ""

    def classify_finding(self, finding: Finding, llm_enabled: bool = False) -> ClassifiedFinding:
        """
        Classify a single finding. Rules applied in priority order.
        
        New order (per CHANGE 5):
        1. File is .example/.sample/.template/.placeholder → LIKELY_FALSE_POSITIVE (no LLM needed)
        2. Known tool placeholder patterns → LIKELY_FALSE_POSITIVE (no LLM needed)
        3. Placeholder substrings in value → LIKELY_FALSE_POSITIVE (no LLM needed)
        4. Constant name (all caps + underscore) → LIKELY_FALSE_POSITIVE (no LLM needed)
        4b. Value is word-like (plain word, not machine-generated) → LIKELY_FALSE_POSITIVE
        5. Entropy < 3.0 → LIKELY_FALSE_POSITIVE (no LLM needed)
        6. LLM ZONE: If llm_enabled AND file exists → call LLM with context
        7. Comment context check (heuristic fallback) → REVIEW_NEEDED
        8. Test directory check → LIKELY_FALSE_POSITIVE
        9. Medium entropy without LLM → REVIEW_NEEDED
        10. Default: CONFIRMED
        """
        # Step 1: File is .example, .sample, .template, .placeholder (extended patterns)
        file_result = self._check_file_patterns(finding.file)
        if file_result:
            return ClassifiedFinding(finding, Classification.LIKELY_FALSE_POSITIVE, file_result)

        # Step 2: Known tool placeholder patterns
        tool_result = self._check_tool_placeholder_patterns(finding.secret_value)
        if tool_result:
            return ClassifiedFinding(finding, Classification.LIKELY_FALSE_POSITIVE, tool_result)

        # Step 3: Placeholder patterns in value
        placeholder_result = self._check_placeholder_patterns(finding.secret_value)
        if placeholder_result:
            return ClassifiedFinding(finding, Classification.LIKELY_FALSE_POSITIVE, placeholder_result)

        # Step 4: Constant/variable name (all caps, underscores, no special chars)
        constant_result = self._check_constant_name(finding.secret_value)
        if constant_result:
            return ClassifiedFinding(finding, Classification.LIKELY_FALSE_POSITIVE, constant_result)

        # Step 4b: Value is word-like (plain word, not machine-generated secret)
        word_result = self._check_value_is_word_like(finding.secret_value, finding.rule_id)
        if word_result:
            return ClassifiedFinding(finding, Classification.LIKELY_FALSE_POSITIVE, word_result)

        # Step 5: Entropy below threshold (< 3.0 is definitely not a secret)
        entropy_result = self._check_entropy(finding.secret_value, finding.rule_id, finding.entropy)
        if entropy_result:
            return ClassifiedFinding(finding, Classification.LIKELY_FALSE_POSITIVE, entropy_result)

        # Step 6: LLM with context (the powerful path) - for all uncertain findings
        if llm_enabled:
            full_path = self.repo_root / finding.file
            if full_path.exists():
                llm_result = self._check_llm_classification(finding, llm_enabled)
                if llm_result is not None:
                    cls, reason = llm_result
                    if cls != Classification.REVIEW_NEEDED:
                        return ClassifiedFinding(finding, cls, reason)

        # Step 7: Comment context check (heuristic fallback)
        comment_result = self._check_comment_context(finding)
        if comment_result:
            return ClassifiedFinding(finding, Classification.REVIEW_NEEDED, comment_result)

        # Step 8: Test directory check
        dir_result = self._check_test_directory(finding.file)
        if dir_result:
            return ClassifiedFinding(finding, Classification.LIKELY_FALSE_POSITIVE, dir_result)

        # Step 9: Medium entropy without LLM → needs review
        entropy = finding.entropy if finding.entropy is not None else _compute_entropy(finding.secret_value)
        if entropy < 3.5 and not llm_enabled:
            return ClassifiedFinding(
                finding,
                Classification.REVIEW_NEEDED,
                f"Medium entropy ({entropy:.2f}) — manual review recommended",
            )

        # Step 10: Default — confirmed real secret
        return ClassifiedFinding(
            finding,
            Classification.CONFIRMED,
            "High entropy, no placeholder patterns, no LLM context available",
        )

    def classify_findings(
        self, findings: list[Finding], llm_enabled: bool = False
    ) -> list[ClassifiedFinding]:
        """Classify a list of findings. Uses parallel LLM calls when llm_enabled."""
        if not llm_enabled or len(findings) <= 3:
            return [self.classify_finding(f, llm_enabled) for f in findings]

        from concurrent.futures import ThreadPoolExecutor, as_completed

        results: list[ClassifiedFinding | None] = [None] * len(findings)
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_idx = {
                executor.submit(self.classify_finding, f, llm_enabled): i
                for i, f in enumerate(findings)
            }
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    results[idx] = future.result()
                except Exception:
                    results[idx] = ClassifiedFinding(
                        findings[idx], Classification.REVIEW_NEEDED, "Classification error"
                    )
        # Safety net: ensure no None entries (e.g., from KeyboardInterrupt)
        for i, r in enumerate(results):
            if r is None:
                results[i] = ClassifiedFinding(
                    findings[i], Classification.REVIEW_NEEDED, "Classification not completed"
                )
        return results  # type: ignore[return-value]

    def classify_value(
        self,
        value: str,
        file_path: str | None = None,
        llm_enabled: bool = False,
    ) -> tuple[Classification, str]:
        """
        Classify a raw secret value (no Finding). Returns (classification, reason).
        Used by `leakfix classify <value>`.
        
        Step order matches classify_finding():
        1. File patterns (if file_path provided)
        2. Tool placeholder patterns
        3. Placeholder patterns
        4. Constant name
        4b. Word-like check
        5. Entropy
        6. LLM (if enabled)
        7. Comment context (skipped - no line context)
        8. Test directory (if file_path provided)
        9. Medium entropy fallback
        10. Default: CONFIRMED
        """
        # Step 1: File patterns (if file_path provided)
        if file_path:
            file_result = self._check_file_patterns(file_path)
            if file_result:
                return Classification.LIKELY_FALSE_POSITIVE, file_result

        # Step 2: Tool placeholder patterns
        tool_result = self._check_tool_placeholder_patterns(value)
        if tool_result:
            return Classification.LIKELY_FALSE_POSITIVE, tool_result

        # Step 3: Placeholder patterns
        placeholder_result = self._check_placeholder_patterns(value)
        if placeholder_result:
            return Classification.LIKELY_FALSE_POSITIVE, placeholder_result

        # Step 4: Constant name
        constant_result = self._check_constant_name(value)
        if constant_result:
            return Classification.LIKELY_FALSE_POSITIVE, constant_result

        # Step 4b: Word-like check (no rule_id available, use "generic")
        word_result = self._check_value_is_word_like(value, "generic")
        if word_result:
            return Classification.LIKELY_FALSE_POSITIVE, word_result

        # Step 5: Entropy (use computed entropy, no rule_id from scanner)
        entropy = _compute_entropy(value)
        entropy_result = self._check_entropy(value, "generic", entropy)
        if entropy_result:
            return Classification.LIKELY_FALSE_POSITIVE, entropy_result

        # Step 6: LLM (if enabled)
        if llm_enabled:
            synthetic_finding = Finding(
                secret_value=value,
                file=file_path or "unknown",
                line=0,
                commit="",
                author="",
                date="",
                rule_id="generic",
                entropy=entropy,
                severity="medium",
            )
            llm_result = self._check_llm_classification(synthetic_finding, llm_enabled)
            if llm_result is not None:
                cls, reason = llm_result
                if cls != Classification.REVIEW_NEEDED:
                    return cls, reason

        # Step 7: Comment context - skipped (no line context available for raw value)

        # Step 8: Test directory (if file_path provided)
        if file_path:
            dir_result = self._check_test_directory(file_path)
            if dir_result:
                return Classification.LIKELY_FALSE_POSITIVE, dir_result

        # Step 9: Medium entropy fallback (without LLM)
        if entropy < 3.5 and not llm_enabled:
            return Classification.REVIEW_NEEDED, f"Medium entropy ({entropy:.2f}) — manual review recommended"

        # Step 10: Default — confirmed real secret
        return Classification.CONFIRMED, "High entropy, no placeholder patterns detected"

    def _check_placeholder_patterns(self, value: str) -> str | None:
        """Check if value contains placeholder substrings. Returns reason or None."""
        value_lower = value.lower()
        for pattern in PLACEHOLDER_PATTERNS:
            if pattern in value_lower:
                return f"Contains placeholder pattern '{pattern}'"

        # Special handling for "1234": only flag if at START or value is ONLY digits
        if "1234" in value:
            if value.startswith("1234") or value_lower.startswith("1234"):
                return "Contains placeholder pattern '1234' at start"
            if value.isdigit():
                return "Value is only digits (placeholder-like)"

        # Special handling for "0000": only flag if repeated (e.g. "00000000") or at start
        if "0000" in value_lower:
            if value_lower.startswith("0000"):
                return "Contains placeholder pattern '0000' at start"
            if re.search(r"0{6,}", value):  # 6+ consecutive zeros
                return "Contains repeated zeros (placeholder-like)"

        return None

    def _check_file_patterns(self, file_path: str) -> str | None:
        """Check if file is .example, .sample, .template, .placeholder or in template path. Returns reason or None."""
        path_lower = file_path.lower().replace("\\", "/")
        # Original suffix check
        for suffix in FILE_PLACEHOLDER_SUFFIXES:
            if suffix in path_lower or path_lower.endswith(suffix):
                return f"File is example/template ({suffix})"
        # Extended path segment check
        for segment in TEMPLATE_PATH_SEGMENTS:
            if segment in path_lower:
                return f"File is in example/template path ({segment})"
        return None

    def _check_entropy(
        self,
        value: str,
        rule_id: str,
        entropy: float | None = None,
    ) -> str | None:
        """Check if entropy is below threshold. Returns reason or None."""
        actual = entropy if entropy is not None else _compute_entropy(value)
        if actual < ENTROPY_THRESHOLD:
            return f"Entropy below {ENTROPY_THRESHOLD} ({actual:.2f})"
        return None

    def _check_comment_context(self, finding: Finding) -> str | None:
        """Check if secret appears in a comment line. Returns reason or None."""
        full_path = self.repo_root / finding.file
        if not full_path.exists():
            return None
        try:
            lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except (OSError, UnicodeDecodeError):
            return None
        line_idx = finding.line - 1
        if line_idx < 0 or line_idx >= len(lines):
            return None
        line = lines[line_idx].strip()
        # Common comment prefixes
        comment_prefixes = ("#", "//", "/*", "*", "<!--", "--", "'", '"')
        for prefix in comment_prefixes:
            if line.startswith(prefix) or line.lstrip().startswith(prefix):
                return "Secret appears in comment line"
        return None

    def _check_constant_name(self, value: str) -> str | None:
        """Check if value looks like a constant/variable name (all caps, underscores). Returns reason or None."""
        if len(value) < 3:
            return None
        # Must be alphanumeric + underscore only
        if not re.match(r"^[A-Za-z0-9_]+$", value):
            return None
        # Should look like a constant: mostly uppercase, or has underscores
        has_underscore = "_" in value
        upper_count = sum(1 for c in value if c.isupper())
        # Constant-like: all caps, or CAPS_WITH_UNDERSCORES
        if has_underscore and upper_count >= 1:
            return "Constant name, not a secret"
        if value.isupper() and len(value) >= 4:
            return "Constant name, not a secret"
        return None

    def _check_value_is_word_like(self, value: str, rule_id: str = "") -> str | None:
        """
        Check if value looks like a human-typed word rather than a machine-generated secret.
        Real secrets are base64/hex/random; fake ones are readable words.
        Heuristic: if value is all alpha + maybe digits, no mixed case alternation,
        length < 24, and entropy < 3.5 → likely a placeholder word.
        
        Bypassed for high-confidence rules (AWS keys, GitHub PATs, etc.) where
        even word-like values may be real tokens.
        """
        # Bypass for high-confidence structured rules
        if rule_id.lower() in HIGH_CONFIDENCE_RULES:
            return None
        if len(value) > 32 or len(value) < 6:
            return None
        # All alphabetic (possibly with digits) — no symbols
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9]*$', value):
            return None
        entropy = _compute_entropy(value)
        if entropy < 3.2:
            return f"Value appears to be a plain word/name (entropy {entropy:.2f}), not a machine-generated secret"
        return None

    def _check_test_directory(self, file_path: str) -> str | None:
        """Check if file is in test/spec/mock/fixture/stub directory. Returns reason or None."""
        path_lower = file_path.lower().replace("\\", "/")
        for pattern in TEST_DIR_PATTERNS:
            if pattern in path_lower:
                return f"File in test/example directory ({pattern})"
        return None

    def _check_llm_classification(
        self,
        finding: Finding,
        llm_enabled: bool,
    ) -> tuple[Classification, str] | None:
        """
        Use ollama LLM to classify a finding with full code context.
        Returns (Classification, reason) or None if ollama not installed.
        """
        try:
            from ollama import Client
        except ImportError:
            _get_logger().info(
                "ollama not found for current Python. Run: leakfix setup --llm"
            )
            return None

        from leakfix.setup_wizard import load_config

        config = load_config()
        model = config.get("llm_model") or "qwen3:0.6b"

        context_lines = self._load_context_lines(finding, window=15)
        file_header = self._load_file_header(finding, n=5)
        file_extension = Path(finding.file).suffix
        file_name = Path(finding.file).name

        prompt = f"""You are a senior security engineer reviewing code for leaked credentials.

## Task
Classify whether the detected value is a REAL credential or a PLACEHOLDER/EXAMPLE.

## Secret Details
- Detected value: `{finding.secret_value}`
- Secret type (gitleaks rule): {finding.rule_id}
- File: {finding.file}
- File name: {file_name}
- File extension: {file_extension}
- Line number: {finding.line}
- Entropy score: {finding.entropy:.2f} (real secrets typically > 4.5)

## File Header (first lines of the file):
{file_header if file_header else "(file not on disk — from git history)"}

## Code Context (±15 lines around the secret):
{context_lines if context_lines else "(context unavailable — secret found in git history only)"}

## Classification Rules

A value is a PLACEHOLDER if ANY of these are true:
1. The file is clearly an example/template (name contains: .example, .sample, .template, README, CONTRIBUTING, docs/)
2. Surrounding lines contain comments like "# replace this", "# fill in", "# your key here", "# copy to .env"
3. The value itself contains obvious placeholder words: YOUR_, REPLACE_, EXAMPLE_, CHANGE_ME, XXXXXXX, 0000, 1234, dummy, test
4. Other values on nearby lines are also obvious placeholders (e.g., DB_HOST=localhost, PASSWORD=changeme)
5. The value is used in a test assertion or mock setup
6. The value appears in documentation (markdown, rst, txt files)
7. The value is surrounded by quotes in a comment or docstring context
8. Multiple similar files exist with the same value (boilerplate pattern)

A value is REAL if ALL of these are true:
1. It is in a file that is NOT an example/template (e.g., actual .env, config.py, settings.py)
2. The surrounding code shows real operational configuration (database URLs, hostnames, ports with real values)
3. The value has high entropy and does not match any placeholder patterns above
4. No surrounding comments suggest it is an example

## Decision
Answer with EXACTLY one word on the first line:
- `REAL` if this is a genuine credential that grants access to a real system
- `PLACEHOLDER` if this is an example, template, dummy, or documentation value

Then on the second line, provide a ONE sentence reason starting with "Reason:".

Example good response:
PLACEHOLDER
Reason: File is .env.example and surrounding lines show other placeholder values like DB_HOST=localhost.
"""

        try:
            client = Client(host="http://localhost:11434", timeout=15.0)
            response = client.chat(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                options={"num_predict": 100, "temperature": 0},
            )
            msg = response.message if hasattr(response, "message") else response.get("message", {})
            msg_content = msg.content if hasattr(msg, "content") else (msg.get("content") if isinstance(msg, dict) else "")
            text = (msg_content or "").strip()
        except Exception as e:
            _get_logger().info("LLM unavailable: %s", e)
            return Classification.REVIEW_NEEDED, "LLM unavailable"

        # Parse response — first non-empty line is REAL or PLACEHOLDER
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        verdict = lines[0].upper() if lines else ""
        reason_line = next((l for l in lines if l.lower().startswith("reason:")), "")
        reason = reason_line.replace("Reason:", "").replace("reason:", "").strip() or "LLM classified"

        if "PLACEHOLDER" in verdict:
            return Classification.LIKELY_FALSE_POSITIVE, f"LLM (context-aware): {reason}"
        if "REAL" in verdict:
            return Classification.CONFIRMED, f"LLM (context-aware): {reason}"
        return Classification.REVIEW_NEEDED, "LLM gave ambiguous response"

    def _check_tool_placeholder_patterns(self, value: str) -> str | None:
        """Check known placeholder patterns for specific tools. Returns reason or None."""
        for pattern, desc in TOOL_PLACEHOLDER_PATTERNS:
            if re.search(pattern, value):
                return f"Matches {desc}"
        # AKIA**************** (exactly 20 chars, all same after AKIA)
        if re.match(r"^AKIA.{16}$", value):
            rest = value[4:]
            if len(set(rest)) == 1:  # all same character
                return "AWS key placeholder (repeated chars)"
        return None
