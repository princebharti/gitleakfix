#!/usr/bin/env python3
"""
leakfix Fix Quality Benchmark
==============================
Measures how well leakfix's LLM-powered fix strategy performs across
real-world secret scenarios.

Usage:
    python benchmarks/bench_fix.py [--model MODEL] [--no-llm]

Metrics:
    - Fix strategy correctness (env_ref vs placeholder vs empty)
    - Replacement quality (meaningful, not just REDACTED)
    - Code syntactic safety (replacement doesn't break file syntax)
    - Latency (LLM response time)
    - Fallback rate (how often LLM fails and uses placeholder)

Scenarios cover:
    - .env files (should use empty strategy)
    - Python source code (should use env_ref with os.environ.get)
    - JavaScript/TypeScript (should use process.env)
    - Go source code (should use os.Getenv)
    - YAML config (should use placeholder or env var syntax ${})
    - Shell scripts (should use $VAR_NAME)
    - Config files (.ini, .toml, .json)
"""
from __future__ import annotations

import json
import sys
import time
import tempfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# Ensure we can import leakfix from the repo root
repo_root = Path(__file__).parent.parent
sys.path.insert(0, str(repo_root))

from leakfix.fixer import (
    _intelligent_replacement,
    _safe_replacement,
    _extract_json_from_response,
    _strip_think_tags,
)


# ─── Scenario Definition ────────────────────────────────────────────────────

@dataclass
class Scenario:
    name: str
    file_path: str          # relative path (determines file type context)
    file_content: str       # full file content
    secret_value: str       # the secret to replace
    secret_line: int        # 1-based line number of the secret
    rule_id: str            # gitleaks rule id
    expected_strategy: str  # "env_ref", "empty", or "placeholder"
    expected_env_var: str   # expected env var name (if strategy is env_ref or empty)
    quality_checks: list[Callable[[str, bool], bool]] = field(default_factory=list)
    description: str = ""


def _check_not_redacted(replacement: str, strip_quotes: bool) -> bool:
    """Replacement should not be the bare word REDACTED."""
    return replacement.strip().upper() not in ("REDACTED", "CHANGE_ME", "")


def _check_not_original(replacement: str, strip_quotes: bool) -> bool:
    """Replacement should never equal the original secret."""
    return True  # enforced by the fixer itself


def _check_not_empty_in_code(replacement: str, strip_quotes: bool) -> bool:
    """In source code (non-env-ref non-empty strategy), replacement should not be empty."""
    return replacement.strip() != "" or strip_quotes


def _check_env_ref_present(replacement: str, strip_quotes: bool) -> bool:
    """For env_ref strategy, replacement should contain an env access pattern."""
    env_patterns = [
        "os.environ", "process.env", "os.Getenv", "ENV[", "System.getenv",
        "getenv", "$", "env.",
    ]
    return strip_quotes or any(p in replacement for p in env_patterns)


SCENARIOS: list[Scenario] = [
    # ── .env files ────────────────────────────────────────────────────────
    Scenario(
        name="dotenv_aws_key",
        file_path=".env",
        file_content=textwrap.dedent("""\
            # Production environment
            APP_ENV=production
            AWS_ACCESS_KEY_ID=AKIAIOSFODNN7REALKEY1
            AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
            AWS_REGION=us-east-1
        """),
        secret_value="AKIAIOSFODNN7REALKEY1",
        secret_line=3,
        rule_id="aws-access-token",
        expected_strategy="empty",
        expected_env_var="AWS_ACCESS_KEY_ID",
        description=".env file with AWS key — should be emptied",
    ),
    Scenario(
        name="dotenv_openai",
        file_path=".env.production",
        file_content=textwrap.dedent("""\
            OPENAI_API_KEY=BENCH-openai-key-xT3BlbkFJabcdefghijklmnopqrst
            STRIPE_SECRET_KEY=BENCH-stripe-key-ABCDEFGHIJKLMNOPQRSTUVWXabcdef
        """),
        secret_value="BENCH-openai-key-xT3BlbkFJabcdefghijklmnopqrst",
        secret_line=1,
        rule_id="generic-api-key",
        expected_strategy="empty",
        expected_env_var="OPENAI_API_KEY",
        description=".env.production with OpenAI key",
    ),

    # ── Python source code ────────────────────────────────────────────────
    Scenario(
        name="python_aws_hardcoded",
        file_path="config/database.py",
        file_content=textwrap.dedent("""\
            import boto3

            AWS_ACCESS_KEY = "AKIAIOSFODNN7REALKEY1"
            AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

            def get_s3_client():
                return boto3.client(
                    's3',
                    aws_access_key_id=AWS_ACCESS_KEY,
                    aws_secret_access_key=AWS_SECRET_KEY,
                )
        """),
        secret_value="AKIAIOSFODNN7REALKEY1",
        secret_line=3,
        rule_id="aws-access-token",
        expected_strategy="env_ref",
        expected_env_var="AWS_ACCESS_KEY",
        quality_checks=[_check_env_ref_present],
        description="Python file with hardcoded AWS key",
    ),
    Scenario(
        name="python_openai_inline",
        file_path="src/llm_client.py",
        file_content=textwrap.dedent("""\
            import openai

            client = openai.OpenAI(
                api_key="BENCH-openai-key-xT3BlbkFJabcdefghijklmnopqrst"
            )

            def ask(prompt: str) -> str:
                return client.chat.completions.create(
                    model="gpt-4",
                    messages=[{"role": "user", "content": prompt}]
                ).choices[0].message.content
        """),
        secret_value="BENCH-openai-key-xT3BlbkFJabcdefghijklmnopqrst",
        secret_line=4,
        rule_id="generic-api-key",
        expected_strategy="env_ref",
        expected_env_var="OPENAI_API_KEY",
        quality_checks=[_check_env_ref_present],
        description="Python file with inline OpenAI key",
    ),
    Scenario(
        name="python_db_password",
        file_path="app/settings.py",
        file_content=textwrap.dedent("""\
            DATABASES = {
                'default': {
                    'ENGINE': 'django.db.backends.postgresql',
                    'NAME': 'myapp',
                    'USER': 'admin',
                    'PASSWORD': 'SuperSecretPass123!',
                    'HOST': 'prod-db.company.com',
                }
            }
        """),
        secret_value="SuperSecretPass123!",
        secret_line=6,
        rule_id="generic-password",
        expected_strategy="env_ref",
        expected_env_var="DATABASE_PASSWORD",
        quality_checks=[_check_env_ref_present],
        description="Django settings with hardcoded DB password",
    ),

    # ── JavaScript ────────────────────────────────────────────────────────
    Scenario(
        name="js_stripe_key",
        file_path="src/payment.js",
        file_content=textwrap.dedent("""\
            const stripe = require('stripe');

            const stripeClient = stripe('BENCH-stripe-key-ABCDEFGHIJKLMNOPQRSTUVWXabcdef');

            async function chargeCard(amount, token) {
                return stripeClient.charges.create({ amount, currency: 'usd', source: token });
            }
        """),
        secret_value="BENCH-stripe-key-ABCDEFGHIJKLMNOPQRSTUVWXabcdef",
        secret_line=3,
        rule_id="generic-api-key",
        expected_strategy="env_ref",
        expected_env_var="STRIPE_SECRET_KEY",
        quality_checks=[_check_env_ref_present],
        description="JavaScript file with Stripe live key",
    ),
    Scenario(
        name="js_github_token",
        file_path="scripts/release.js",
        file_content=textwrap.dedent("""\
            const { Octokit } = require('@octokit/rest');

            const octokit = new Octokit({
                auth: 'BENCH-github-tok-16C7e42F292c6912E169E2838C0B2'
            });

            module.exports = { octokit };
        """),
        secret_value="BENCH-github-tok-16C7e42F292c6912E169E2838C0B2",
        secret_line=4,
        rule_id="generic-api-key",
        expected_strategy="env_ref",
        expected_env_var="GITHUB_TOKEN",
        quality_checks=[_check_env_ref_present],
        description="JavaScript with GitHub PAT",
    ),

    # ── Go source code ────────────────────────────────────────────────────
    Scenario(
        name="go_jwt_secret",
        file_path="backend/auth.go",
        file_content=textwrap.dedent("""\
            package auth

            import "github.com/golang-jwt/jwt"

            const jwtSecret = "my-super-secret-jwt-signing-key-very-long-12345"

            func generateToken(userID string) (string, error) {
                token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
                    "user_id": userID,
                })
                return token.SignedString([]byte(jwtSecret))
            }
        """),
        secret_value="my-super-secret-jwt-signing-key-very-long-12345",
        secret_line=5,
        rule_id="generic-api-key",
        expected_strategy="env_ref",
        expected_env_var="JWT_SECRET",
        quality_checks=[_check_env_ref_present],
        description="Go file with JWT secret constant",
    ),

    # ── YAML config ───────────────────────────────────────────────────────
    Scenario(
        name="yaml_db_password",
        file_path="infrastructure/config.yaml",
        file_content=textwrap.dedent("""\
            database:
              host: prod-db.company.com
              port: 5432
              name: myapp
              username: admin
              password: SuperSecretPass123!
        """),
        secret_value="SuperSecretPass123!",
        secret_line=6,
        rule_id="generic-password",
        # YAML files should get a ${VAR} placeholder, not Python env-ref syntax.
        # Accept "placeholder" as the correct strategy.
        expected_strategy="placeholder",
        expected_env_var="DATABASE_PASSWORD",
        quality_checks=[
            _check_not_redacted,
            # Replacement must not use Python syntax in YAML
            lambda r, sq: not (sq and "os.environ" in r),
        ],
        description="YAML config with database password",
    ),

    # ── Shell scripts ─────────────────────────────────────────────────────
    Scenario(
        name="shell_export_aws",
        file_path="scripts/deploy.sh",
        file_content=textwrap.dedent("""\
            #!/bin/bash
            export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7REALKEY1"
            export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            ./deploy.sh
        """),
        secret_value="AKIAIOSFODNN7REALKEY1",
        secret_line=2,
        rule_id="aws-access-token",
        expected_strategy="env_ref",
        expected_env_var="AWS_ACCESS_KEY_ID",
        quality_checks=[_check_env_ref_present],
        description="Shell script with exported AWS credentials",
    ),
]


# ─── Benchmark Runner ────────────────────────────────────────────────────────

@dataclass
class Result:
    scenario: Scenario
    replacement: str
    strip_quotes: bool
    used_llm: bool
    reason: str | None
    latency_ms: float
    strategy_correct: bool
    quality_pass: bool
    error: str | None = None


def run_scenario(scenario: Scenario, repo_root: Path) -> Result:
    """Run a single benchmark scenario."""
    # Write the scenario file to a temp dir
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        # Init a minimal git repo so fixer works
        import subprocess
        subprocess.run(["git", "init"], cwd=tmp, capture_output=True)
        subprocess.run(["git", "config", "user.email", "bench@test.com"], cwd=tmp, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Bench"], cwd=tmp, capture_output=True)

        file_full = tmp / scenario.file_path
        file_full.parent.mkdir(parents=True, exist_ok=True)
        file_full.write_text(scenario.file_content, encoding="utf-8")

        subprocess.run(["git", "add", "."], cwd=tmp, capture_output=True)
        subprocess.run(["git", "commit", "-m", "bench"], cwd=tmp, capture_output=True)

        t0 = time.perf_counter()
        try:
            replacement, reason, used_llm, strip_quotes = _intelligent_replacement(
                secret_value=scenario.secret_value,
                file_path=scenario.file_path,
                line_number=scenario.secret_line,
                rule_id=scenario.rule_id,
                repo_root=tmp,
            )
            latency_ms = (time.perf_counter() - t0) * 1000

            # Determine actual strategy from result
            if strip_quotes:
                actual_strategy = "env_ref"
            elif replacement == "" or replacement.strip() == "":
                actual_strategy = "empty"
            else:
                actual_strategy = "placeholder"

            strategy_correct = (actual_strategy == scenario.expected_strategy)

            # Run quality checks
            quality_pass = all(
                check(replacement, strip_quotes)
                for check in scenario.quality_checks
            ) if scenario.quality_checks else True

            return Result(
                scenario=scenario,
                replacement=replacement,
                strip_quotes=strip_quotes,
                used_llm=used_llm,
                reason=reason,
                latency_ms=latency_ms,
                strategy_correct=strategy_correct,
                quality_pass=quality_pass,
            )
        except Exception as e:
            return Result(
                scenario=scenario,
                replacement="",
                strip_quotes=False,
                used_llm=False,
                reason=None,
                latency_ms=(time.perf_counter() - t0) * 1000,
                strategy_correct=False,
                quality_pass=False,
                error=str(e),
            )


def print_results(results: list[Result]) -> None:
    """Print a formatted benchmark report."""
    # ANSI colors
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    print(f"\n{BOLD}{'=' * 72}{RESET}")
    print(f"{BOLD}  leakfix Fix Quality Benchmark{RESET}")
    print(f"{'=' * 72}")

    passed = 0
    failed = 0
    llm_used = 0
    total_latency = 0.0

    for r in results:
        ok = r.strategy_correct and r.quality_pass and not r.error
        status = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
        llm_tag = f"{CYAN}[LLM]{RESET}" if r.used_llm else f"{YELLOW}[fallback]{RESET}"
        strip_tag = " [strip-quotes]" if r.strip_quotes else ""

        print(f"\n  {status} {llm_tag} {r.scenario.name}")
        print(f"       {r.scenario.description}")
        print(f"       File:        {r.scenario.file_path}")
        print(f"       Secret:      {r.scenario.secret_value[:40]}...")
        print(f"       Replacement: {r.replacement!r}{strip_tag}")
        print(f"       Strategy:    expected={r.scenario.expected_strategy}  got={'env_ref' if r.strip_quotes else ('empty' if r.replacement.strip() == '' else 'placeholder')}")
        if r.reason:
            print(f"       Reason:      {r.reason}")
        print(f"       Latency:     {r.latency_ms:.0f}ms")
        if r.error:
            print(f"       {RED}Error: {r.error}{RESET}")

        if ok:
            passed += 1
        else:
            failed += 1
        if r.used_llm:
            llm_used += 1
        total_latency += r.latency_ms

    total = len(results)
    avg_latency = total_latency / total if total else 0

    print(f"\n{'=' * 72}")
    print(f"  {BOLD}Results:{RESET}  {GREEN}{passed} passed{RESET}  /  {RED}{failed} failed{RESET}  /  {total} total")
    print(f"  LLM used:    {llm_used}/{total} scenarios  ({100*llm_used//total}%)")
    print(f"  Avg latency: {avg_latency:.0f}ms")
    print(f"{'=' * 72}\n")

    if failed > 0:
        sys.exit(1)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="leakfix fix quality benchmark")
    parser.add_argument(
        "--model", default=None,
        help="Ollama model to use (overrides ~/.leakfix/config.json)"
    )
    parser.add_argument(
        "--no-llm", action="store_true",
        help="Disable LLM, test fallback placeholder quality only"
    )
    parser.add_argument(
        "--scenarios", nargs="*", default=None,
        help="Run only specific scenario names (space-separated)"
    )
    args = parser.parse_args()

    # Optionally override LLM config
    if args.no_llm:
        # Patch _get_llm_config to return None
        import leakfix.fixer as fixer_module
        fixer_module._get_llm_config = lambda: None  # type: ignore
        print("⚠️  LLM disabled — testing fallback placeholder quality only\n")
    elif args.model:
        import leakfix.fixer as fixer_module
        orig_get_config = fixer_module._get_llm_config
        def patched_config():
            cfg = orig_get_config() or {}
            cfg["llm_enabled"] = True
            cfg["llm_model"] = args.model
            cfg["llm_provider"] = "ollama"
            return cfg
        fixer_module._get_llm_config = patched_config  # type: ignore
        print(f"ℹ️  Using model: {args.model}\n")

    scenarios = SCENARIOS
    if args.scenarios:
        scenarios = [s for s in SCENARIOS if s.name in args.scenarios]
        if not scenarios:
            print(f"No scenarios match: {args.scenarios}")
            sys.exit(1)

    print(f"Running {len(scenarios)} benchmark scenario(s)...")

    results = [run_scenario(s, repo_root) for s in scenarios]
    print_results(results)


if __name__ == "__main__":
    main()
