"""False positive classifier - filters placeholder and example secrets from real leaks."""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from leakfix.scanner import Finding

# Log to ~/.leakfix/leakfix.log when ollama is unavailable
_LEAKFIX_HOME = Path.home() / ".leakfix"
_LEAKFIX_LOG = _LEAKFIX_HOME / "leakfix.log"
_logger: logging.Logger | None = None


def _get_logger() -> logging.Logger:
    """Get or create logger for leakfix."""
    global _logger
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

# Entropy threshold below which we consider low entropy
ENTROPY_THRESHOLD = 3.0


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

    def classify_finding(self, finding: Finding, llm_enabled: bool = False) -> ClassifiedFinding:
        """Classify a single finding. Rules applied in priority order."""
        # 1. File is .example, .sample, .template, .placeholder
        file_result = self._check_file_patterns(finding.file)
        if file_result:
            return ClassifiedFinding(finding, Classification.LIKELY_FALSE_POSITIVE, file_result)

        # 2. Placeholder patterns in value
        placeholder_result = self._check_placeholder_patterns(finding.secret_value)
        if placeholder_result:
            return ClassifiedFinding(finding, Classification.LIKELY_FALSE_POSITIVE, placeholder_result)

        # 3. Constant/variable name (all caps, underscores, no special chars)
        constant_result = self._check_constant_name(finding.secret_value)
        if constant_result:
            return ClassifiedFinding(finding, Classification.LIKELY_FALSE_POSITIVE, constant_result)

        # 4. Entropy below threshold
        entropy_result = self._check_entropy(finding.secret_value, finding.rule_id, finding.entropy)
        if entropy_result:
            return ClassifiedFinding(finding, Classification.LIKELY_FALSE_POSITIVE, entropy_result)

        # 5. File in test/spec/mock/fixture/stub directory
        dir_result = self._check_test_directory(finding.file)
        if dir_result:
            return ClassifiedFinding(finding, Classification.LIKELY_FALSE_POSITIVE, dir_result)

        # 6. Secret in comment line
        comment_result = self._check_comment_context(finding)
        if comment_result:
            if llm_enabled:
                llm_result = self._check_llm_classification(finding, llm_enabled)
                if llm_result is not None:
                    cls, reason = llm_result
                    return ClassifiedFinding(finding, cls, reason)
            return ClassifiedFinding(finding, Classification.REVIEW_NEEDED, comment_result)

        # 7. Known tool placeholder patterns
        tool_result = self._check_tool_placeholder_patterns(finding.secret_value)
        if tool_result:
            return ClassifiedFinding(finding, Classification.LIKELY_FALSE_POSITIVE, tool_result)

        # 8. Default: CONFIRMED
        return ClassifiedFinding(
            finding,
            Classification.CONFIRMED,
            "High entropy, no placeholder patterns detected",
        )

    def classify_findings(
        self, findings: list[Finding], llm_enabled: bool = False
    ) -> list[ClassifiedFinding]:
        """Classify a list of findings."""
        return [self.classify_finding(f, llm_enabled) for f in findings]

    def classify_value(
        self,
        value: str,
        file_path: str | None = None,
        llm_enabled: bool = False,
    ) -> tuple[Classification, str]:
        """
        Classify a raw secret value (no Finding). Returns (classification, reason).
        Used by `leakfix classify <value>`.
        """
        # 1. File patterns (if file_path provided)
        if file_path:
            file_result = self._check_file_patterns(file_path)
            if file_result:
                return Classification.LIKELY_FALSE_POSITIVE, file_result

        # 2. Placeholder patterns
        placeholder_result = self._check_placeholder_patterns(value)
        if placeholder_result:
            return Classification.LIKELY_FALSE_POSITIVE, placeholder_result

        # 3. Constant name
        constant_result = self._check_constant_name(value)
        if constant_result:
            return Classification.LIKELY_FALSE_POSITIVE, constant_result

        # 4. Entropy (use computed entropy, no rule_id from scanner)
        entropy = _compute_entropy(value)
        entropy_result = self._check_entropy(value, "generic", entropy)
        if entropy_result:
            return Classification.LIKELY_FALSE_POSITIVE, entropy_result

        # 5. Test directory (if file_path provided)
        if file_path:
            dir_result = self._check_test_directory(file_path)
            if dir_result:
                return Classification.LIKELY_FALSE_POSITIVE, dir_result

        # 6. Tool placeholder patterns
        tool_result = self._check_tool_placeholder_patterns(value)
        if tool_result:
            return Classification.LIKELY_FALSE_POSITIVE, tool_result

        # 7. Would be CONFIRMED - optionally use LLM as second opinion
        if llm_enabled:
            synthetic_finding = Finding(
                secret_value=value,
                file=file_path or "unknown",
                line=0,
                commit="",
                author="",
                date="",
                rule_id="generic",
                entropy=_compute_entropy(value),
                severity="medium",
            )
            llm_result = self._check_llm_classification(synthetic_finding, llm_enabled)
            if llm_result is not None:
                cls, reason = llm_result
                # Only use LLM result when it gives a definitive answer (not "LLM unavailable")
                if cls != Classification.REVIEW_NEEDED:
                    return cls, reason

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
        """Check if file is .example, .sample, .template, .placeholder. Returns reason or None."""
        path_lower = file_path.lower().replace("\\", "/")
        for suffix in FILE_PLACEHOLDER_SUFFIXES:
            if suffix in path_lower or path_lower.endswith(suffix):
                return f"File is example/template ({suffix})"
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
        Use ollama LLM to classify a REVIEW_NEEDED finding.
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

        prompt = f"""You are a security expert reviewing code for leaked credentials.

Is this a real secret credential or a placeholder/example value?

Value: {finding.secret_value}
File: {finding.file}
Secret type detected: {finding.rule_id}

Rules:
- REAL = actual credential that would grant access to a system
- PLACEHOLDER = example, template, dummy, or documentation value

Answer with only one word: REAL or PLACEHOLDER"""

        try:
            client = Client(host="http://localhost:11434", timeout=10.0)
            response = client.chat(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                options={"num_predict": 50},
            )
            msg = response.message if hasattr(response, "message") else response.get("message", {})
            # qwen3 thinking models return answer in content, reasoning in thinking
            msg_content = msg.content if hasattr(msg, "content") else (msg.get("content") if isinstance(msg, dict) else "")
            msg_thinking = msg.thinking if hasattr(msg, "thinking") else ""
            # Use content first, fall back to thinking if content empty
            text = (msg_content or msg_thinking or "").upper()
        except Exception as e:
            _get_logger().info("LLM unavailable (ollama not running?): %s", e)
            return Classification.REVIEW_NEEDED, "LLM unavailable"

        if "REAL" in text:
            return Classification.CONFIRMED, "LLM classified as real credential"
        if "PLACEHOLDER" in text:
            return Classification.LIKELY_FALSE_POSITIVE, "LLM classified as placeholder"
        return Classification.REVIEW_NEEDED, "LLM unavailable"

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
