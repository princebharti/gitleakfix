"""Main CLI for leakfix - secret detection and remediation."""

import json
import os
import sys
from pathlib import Path

import click
from rich import box as rich_box
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table

from leakfix import __version__
from leakfix.classifier import Classification, Classifier, ClassifiedFinding
from leakfix.fixer import Fixer
from leakfix.gitignore import GitignoreManager
from leakfix.hooks import HookManager
from leakfix.org_scanner import OrgScanner, RepoResult
from leakfix.reporter import Reporter
from leakfix.scanner import Finding, Scanner
from leakfix.setup_wizard import (
    check_dependencies_only,
    load_config,
    run_setup,
)
from leakfix.utils import (
    check_gitleaks_installed,
    check_git_filter_repo_installed,
    get_repo_root,
    has_commits,
    is_git_repo,
    mask_secret as _mask_secret,
)

console = Console()

# Import ui.py components with graceful fallback
try:
    from leakfix.ui import (
        print_banner as _print_banner,
        print_section_header,
        print_success,
        print_error,
        print_warning,
        glow_progress_kwargs,
        APPLE_PURPLE, APPLE_BLUE_PURPLE, APPLE_PINK_RED,
        APPLE_ORANGE, APPLE_VIOLET, APPLE_PINK,
    )
    _UI_AVAILABLE = True
except ImportError:
    _UI_AVAILABLE = False


def _check_llm_setup() -> bool:
    """Check if LLM is configured. Prompts user to run setup if not."""
    from leakfix.setup_wizard import load_config, run_setup

    config = load_config()

    if not config.get("setup_complete"):
        console.print("[yellow]⚠️  leakfix setup not completed.[/yellow]")
        try:
            ans = input("Run setup now? [Y/n]: ").strip().lower()
            if ans != "n" and ans != "no":
                run_setup()
                config = load_config()
            else:
                return False
        except (EOFError, KeyboardInterrupt):
            return False

    if not config.get("llm_enabled"):
        console.print("[yellow]⚠️  LLM enhancement not enabled.[/yellow]")
        try:
            ans = input(
                "Enable now? (requires ~2GB download) [Y/n]: "
            ).strip().lower()
            if ans != "n" and ans != "no":
                run_setup(llm_only=True)
                config = load_config()
            else:
                return False
        except (EOFError, KeyboardInterrupt):
            return False

    return config.get("llm_enabled", False)


def _filter_by_severity(findings: list[Finding], severity: str | None) -> list[Finding]:
    """Filter findings by severity (high, medium, low)."""
    if not severity:
        return findings
    severity_map = {"high": ["high"], "medium": ["medium"], "low": ["low"]}
    allowed = severity_map.get(severity.lower(), [])
    if not allowed:
        return findings
    return [f for f in findings if f.severity.lower() in allowed]


def _format_scanner_badge(scanner: str) -> str:
    """Format scanner source as a colored badge."""
    if scanner == "both":
        return "[bold green]both[/bold green]"
    elif scanner == "ggshield":
        return "[cyan]ggshield[/cyan]"
    else:
        return "[dim]gitleaks[/dim]"


def _severity_dot(severity: str) -> str:
    """Return a colored severity dot indicator."""
    s = severity.lower()
    if s == "high":
        return f"[bold #FF6778]●[/bold #FF6778]"
    elif s == "medium":
        return f"[bold #FFBA71]◉[/bold #FFBA71]"
    return f"[dim #6E6E73]○[/dim #6E6E73]"


def _commit_or_staged(f: Finding) -> str:
    """Return short commit hash, or 'staged' badge if no commit (i.e. from staged changes)."""
    if not f.commit:
        return "[bold #FFBA71]staged[/bold #FFBA71]"
    return f.commit[:7]


def _format_table(findings: list[Finding], title: str = "Scan Results") -> None:
    """Print findings as an Apple Intelligence styled table."""
    table = Table(
        title=f"[bold #BC82F3]leakfix[/bold #BC82F3]  [dim #6E6E73]{title}[/dim #6E6E73]",
        header_style="bold #8D9FFF",
        border_style="#3A3A3C",
        box=rich_box.SIMPLE_HEAD,
        row_styles=["", "dim"],
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("File / Path", style="#8D9FFF", no_wrap=True, max_width=36)
    table.add_column("Line", justify="right", style="dim", width=5)
    table.add_column("Secret Type", style="#F5B9EA", no_wrap=True, max_width=22)
    table.add_column("Match", style="dim", no_wrap=True, max_width=38)
    table.add_column("Sev", justify="center", width=3)
    table.add_column("Source", justify="center", no_wrap=True)
    for f in findings:
        match_display = (getattr(f, "match_context", "") or _mask_secret(f.secret_value)).replace("\n", " ").replace("\r", "")
        if len(match_display) > 36:
            match_display = match_display[:33] + "…"
        file_display = f.file
        if len(file_display) > 34:
            file_display = "…" + file_display[-33:]
        table.add_row(
            file_display,
            str(f.line) if f.line else "—",
            f.rule_id,
            match_display,
            _severity_dot(f.severity),
            _commit_or_staged(f),
        )
    console.print()
    console.print(table)
    file_count = len({f.file for f in findings})
    console.print(f"  [dim #6E6E73]{len(findings)} secret(s) across {file_count} file(s)[/dim #6E6E73]")


def _format_json(findings: list[Finding]) -> None:
    """Output findings as JSON array. Secrets are masked for security."""
    data = [
        {
            "file": f.file,
            "line": f.line,
            "commit": f.commit,
            "author": f.author,
            "date": f.date,
            "rule_id": f.rule_id,
            "entropy": f.entropy,
            "severity": f.severity,
            "scanner": getattr(f, 'scanner', 'gitleaks'),
            "secret_masked": _mask_for_smart_display(f.secret_value),
        }
        for f in findings
    ]
    console.print(json.dumps(data, indent=2))


def _mask_for_smart_display(secret: str, max_visible: int = 7) -> str:
    """Mask secret for smart scan display: first N chars + ***."""
    if len(secret) <= max_visible:
        return secret[:4] + "***" if len(secret) > 4 else "****"
    return secret[:max_visible] + "***"


def _llm_display_name(cls: Classification) -> str:
    """Display name for LLM classification output."""
    if cls == Classification.LIKELY_FALSE_POSITIVE:
        return "FALSE POSITIVE"
    return cls.name


AI_BANNER = """
[bold]  [magenta]●[/magenta] [blue]●[/blue] [#8D9FFF]●[/#8D9FFF]  [bold white]leakfix[/bold white]  [dim]— intelligent secret detection[/dim][/bold]
"""

def _format_smart_scan(classified: list[ClassifiedFinding], repo_root: Path) -> None:
    """Output format for --smart scan: grouped by classification with Apple Intelligence theme."""
    if _UI_AVAILABLE:
        _print_banner()
    else:
        console.print(AI_BANNER)

    confirmed = [c for c in classified if c.classification == Classification.CONFIRMED]
    false_positives = [
        c for c in classified if c.classification == Classification.LIKELY_FALSE_POSITIVE
    ]
    review_needed = [c for c in classified if c.classification == Classification.REVIEW_NEEDED]

    def scanner_tag(finding: Finding) -> str:
        scanner = getattr(finding, "scanner", "gitleaks")
        if scanner == "both":
            return "[bold #30D158][both][/bold #30D158] "
        elif scanner == "ggshield":
            return "[#8D9FFF][gg][/#8D9FFF] "
        return ""

    def _loc(finding: Finding) -> str:
        """Format file:line location clearly."""
        line_part = f":{finding.line}" if finding.line else ""
        return f"{finding.file}{line_part}"

    def _source_badge(finding: Finding) -> str:
        """Show 'staged' or short commit hash as source badge."""
        if not finding.commit:
            return "[bold #FFBA71]staged[/bold #FFBA71]"
        return f"[dim #6E6E73]{finding.commit[:7]}[/dim #6E6E73]"

    if confirmed:
        console.print(f"\n  [bold #FF6778]● CONFIRMED SECRETS[/bold #FF6778]  [dim #6E6E73]{len(confirmed)} found[/dim #6E6E73]")
        console.print(f"  [dim #3A3A3C]{'─' * 54}[/dim #3A3A3C]")
        for c in confirmed:
            masked = _mask_for_smart_display(c.finding.secret_value)
            entropy = c.finding.entropy
            sev = c.finding.severity.upper()
            stag = scanner_tag(c.finding)
            sev_color = "#FF6778" if sev == "HIGH" else ("#FFBA71" if sev == "MEDIUM" else "#6E6E73")
            match_ctx = getattr(c.finding, "match_context", "")
            console.print(
                f"  [bold #FF6778]●[/bold #FF6778]  {stag}"
                f"[bold #8D9FFF]{_loc(c.finding)}[/bold #8D9FFF]  "
                f"[dim #F5B9EA]{c.finding.rule_id}[/dim #F5B9EA]  "
                f"{_source_badge(c.finding)}"
            )
            if match_ctx:
                display_match = match_ctx.replace("\n", " ").replace("\r", "")
                if len(display_match) > 60:
                    display_match = display_match[:57] + "…"
                console.print(f"     [dim]match[/dim] [dim #8D9FFF]{display_match}[/dim #8D9FFF]")
            console.print(
                f"     [dim]value[/dim] [bold]{masked}[/bold]  "
                f"[dim]entropy {entropy:.2f}  [bold {sev_color}]{sev}[/bold {sev_color}][/dim]"
            )
            if "LLM (context-aware):" in c.reason or "LLM classified" in c.reason:
                console.print(f"     [dim #AA6EEE]↳ {c.reason}[/dim #AA6EEE]")
            elif getattr(c.finding, "scanner", "gitleaks") == "both":
                console.print(f"     [dim #30D158]↳ detected by both gitleaks and ggshield[/dim #30D158]")
            console.print()

    if false_positives:
        console.print(f"  [bold #8D9FFF]○ FALSE POSITIVES[/bold #8D9FFF]  [dim #6E6E73]{len(false_positives)} skipped[/dim #6E6E73]")
        console.print(f"  [dim #3A3A3C]{'─' * 54}[/dim #3A3A3C]")
        for c in false_positives:
            stag = scanner_tag(c.finding)
            console.print(
                f"  [dim #6E6E73]○[/dim #6E6E73]  {stag}"
                f"[dim #8D9FFF]{_loc(c.finding)}[/dim #8D9FFF]  "
                f"[dim]{c.finding.rule_id}[/dim]  "
                f"{_source_badge(c.finding)}"
            )
            console.print(f"     [dim #6E6E73]↳ {c.reason}[/dim #6E6E73]")
        console.print()

    if review_needed:
        console.print(f"  [bold #FFBA71]◉ REVIEW NEEDED[/bold #FFBA71]  [dim #6E6E73]{len(review_needed)} items[/dim #6E6E73]")
        console.print(f"  [dim #3A3A3C]{'─' * 54}[/dim #3A3A3C]")
        for c in review_needed:
            stag = scanner_tag(c.finding)
            match_ctx = getattr(c.finding, "match_context", "")
            console.print(
                f"  [bold #FFBA71]◉[/bold #FFBA71]  {stag}"
                f"[#8D9FFF]{_loc(c.finding)}[/#8D9FFF]  "
                f"[dim]{c.finding.rule_id}[/dim]  "
                f"{_source_badge(c.finding)}"
            )
            if match_ctx:
                display_match = match_ctx.replace("\n", " ").replace("\r", "")
                if len(display_match) > 60:
                    display_match = display_match[:57] + "…"
                console.print(f"     [dim]match[/dim] [dim #8D9FFF]{display_match}[/dim #8D9FFF]")
            console.print(f"     [dim #FFBA71]↳ {c.reason}[/dim #FFBA71]")
        console.print()

    # Summary footer with table for actionable findings
    actionable = confirmed + review_needed
    if actionable:
        _format_table([c.finding for c in actionable], title="Findings Summary")

    console.print()
    console.print(
        f"  [bold #FF6778]{len(confirmed)} confirmed[/bold #FF6778]"
        f"  [dim #6E6E73]·[/dim #6E6E73]  "
        f"[#8D9FFF]{len(false_positives)} skipped[/#8D9FFF]"
        f"  [dim #6E6E73]·[/dim #6E6E73]  "
        f"[#FFBA71]{len(review_needed)} needs review[/#FFBA71]"
        f"  [dim #6E6E73]·[/dim #6E6E73]  [bold #BC82F3]leakfix[/bold #BC82F3]"
    )


def _format_html(findings: list[Finding], output_path: Path) -> None:
    """Save findings as HTML report to leakfix-report.html."""
    rows = "".join(
        f"""
        <tr>
            <td>{f.file}</td>
            <td>{f.rule_id}</td>
            <td>{f.line}</td>
            <td>{f.severity.upper()}</td>
            <td>{f.commit[:7] if len(f.commit) >= 7 else f.commit}</td>
            <td>{f.author or "-"}</td>
        </tr>"""
        for f in findings
    )
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>leakfix Scan Report</title>
    <style>
        body {{ font-family: system-ui, sans-serif; margin: 2rem; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #333; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
    </style>
</head>
<body>
    <h1>leakfix Scan Results</h1>
    <p>Found {len(findings)} secret(s) in {len({f.file for f in findings})} file(s)</p>
    <table>
        <thead>
            <tr>
                <th>File</th>
                <th>Secret Type</th>
                <th>Line</th>
                <th>Severity</th>
                <th>Commit</th>
                <th>Author</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</body>
</html>"""
    output_path.write_text(html)
    console.print(f"Report saved to [bold]{output_path}[/bold]")


@click.group()
@click.version_option(version=__version__)
def main():
    """leakfix - Detect, remove, and prevent secrets in git repositories."""
    pass


@main.command()
def ui():
    """Interactive TUI wizard (Apple Intelligence style)."""
    from leakfix.wizard_app import LeakfixWizardApp
    LeakfixWizardApp().run()


@main.command()
@click.option(
    "--llm",
    is_flag=True,
    help="Jump straight to LLM setup only.",
)
@click.option(
    "--check",
    is_flag=True,
    help="Just check dependencies, no prompts.",
)
@click.option(
    "--reset",
    is_flag=True,
    help="Reset config and re-run full setup.",
)
def setup(llm: bool, check: bool, reset: bool):
    """Interactive setup wizard."""
    if check:
        from leakfix.setup_wizard import _get_installed_ollama_models

        status = check_dependencies_only()
        console.print("\nDependency status:")
        console.print(
            f"  Python: {status.get('python_version', '?')} ({status.get('python_executable', '?')})"
        )
        icon = "[green]✅[/green]" if status.get("ollama_pip") else "[red]❌[/red]"
        console.print(f"  {icon} ollama (Python)")
        for name in ("gitleaks", "git-filter-repo", "python3", "ollama"):
            found = status.get(name, False)
            icon = "[green]✅[/green]" if found else "[red]❌[/red]"
            label = "ollama (CLI)" if name == "ollama" else name
            console.print(f"  {icon} {label}")

        # Show ggshield status (optional dependency)
        ggshield_found = status.get("ggshield", False)
        if ggshield_found:
            console.print(f"  [green]✅[/green] ggshield")
        else:
            console.print(f"  [yellow]⚠️[/yellow]  ggshield [dim](optional)[/dim]")

        if not status["gitleaks"]:
            console.print("\n  Install: brew install gitleaks")
        if not status["git-filter-repo"]:
            console.print("  Install: brew install git-filter-repo")
        if not ggshield_found:
            console.print("  Install ggshield (optional): brew install ggshield")
        if not status.get("ollama_pip"):
            console.print("  Install ollama Python: leakfix setup --llm")

        # Show LLM configuration
        config = load_config()
        console.print("\nLLM configuration:")
        provider = config.get("llm_provider", "ollama")
        model = config.get("llm_model")
        llm_enabled = config.get("llm_enabled", False)

        console.print(f"  Provider : {provider}")
        console.print(f"  Model    : {model or '(not configured)'}")

        if llm_enabled:
            if provider == "ollama":
                models = _get_installed_ollama_models()
                if models:
                    console.print(f"  Status   : [green]✅ running ({len(models)} models installed)[/green]")
                else:
                    console.print("  Status   : [yellow]⚠️  ollama not running or no models[/yellow]")
            else:
                base_url = config.get("llm_base_url", "")
                console.print(f"  Base URL : {base_url}")
                console.print("  Status   : [dim]configured (OpenAI-compatible)[/dim]")
        else:
            console.print("  Status   : [dim]disabled[/dim]")

        core_ok = status["gitleaks"] and status["git-filter-repo"]
        sys.exit(0 if core_ok else 1)

    success = run_setup(llm_only=llm, reset=reset)
    sys.exit(0 if success else 1)


def _format_hook_mode(findings: list[Finding], dangerous_files: list[str], path: Path) -> None:
    """Output format for pre-commit hook: masked secrets, compact, never show full secret."""
    console.print("\n🔍 leakfix pre-commit scan\n")
    if findings:
        console.print("❌ SECRETS DETECTED - Commit blocked\n")
        for f in findings:
            masked = _mask_secret(f.secret_value)
            console.print(f"  {f.file}:{f.line} - {f.rule_id} ({masked})")
    if dangerous_files:
        console.print("\n⚠️  DANGEROUS FILES in staging:")
        for f in dangerous_files:
            console.print(f"  {f} - should be in .gitignore")
    if findings or dangerous_files:
        console.print("\n💡 To fix:")
        if findings:
            console.print("   Run: leakfix fix")
        if dangerous_files:
            console.print("   Or add to .gitignore: leakfix gitignore")
        console.print("\nTo bypass this check (not recommended):")
        console.print("   git commit --no-verify\n")


@main.command()
@click.option(
    "--history",
    is_flag=True,
    help="Scan full git history instead of working directory.",
)
@click.option(
    "--all",
    "scan_all_flag",
    is_flag=True,
    help="Scan both working directory and git history.",
)
@click.option(
    "--staged",
    is_flag=True,
    help="Scan only staged files (for pre-commit hook).",
)
@click.option(
    "--hook-mode",
    is_flag=True,
    help="Special output format for hooks: mask secrets, check dangerous files.",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["table", "json", "html"]),
    default="table",
    help="Output format (default: table).",
)
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["high", "medium", "low"]),
    default=None,
    help="Filter findings by severity.",
)
@click.option(
    "--raw",
    "raw_flag",
    is_flag=True,
    help="Disable smart filtering, show all findings including false positives.",
)
@click.option(
    "--llm",
    is_flag=True,
    help="Use LLM to classify REVIEW_NEEDED findings (requires ollama).",
)
@click.option(
    "--include-untracked",
    is_flag=True,
    help="Include untracked/gitignored files (only meaningful with --history; use --all to scan everything).",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Show detailed output including all skipped files.",
)
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
def scan(
    path: Path,
    history: bool,
    scan_all_flag: bool,
    staged: bool,
    hook_mode: bool,
    output: str,
    severity: str | None,
    raw_flag: bool,
    llm: bool,
    include_untracked: bool,
    verbose: bool,
):
    """Scan repository for leaked secrets."""
    # Smart mode (classification) only applies to table output — json/html need raw findings
    smart = not raw_flag and output == "table"
    
    if not check_gitleaks_installed():
        console.print("[red]gitleaks not found. Run: brew install gitleaks[/red]")
        sys.exit(2)

    if not is_git_repo(path):
        console.print("[red]Not a git repository. Run from a git repo or specify a path.[/red]")
        sys.exit(2)

    repo_root = get_repo_root(path) or path
    scanner = Scanner(path)

    # Show ggshield availability message
    ggshield_msg = scanner.get_scanner_info_message()
    if ggshield_msg:
        console.print(f"[dim]{ggshield_msg}[/dim]")

    _scan_all_history_only_count = 0  # tracks secrets only in history (not in working files)

    # Scan with progress bar (Apple Intelligence glow style if available)
    if _UI_AVAILABLE:
        _pkwargs = glow_progress_kwargs()
        _columns = _pkwargs.pop("columns", None)
        _progress_ctx = Progress(*_columns, console=console, **_pkwargs)
    else:
        _progress_ctx = Progress(
            SpinnerColumn(spinner_name="dots", style="bold magenta"),
            TextColumn("[bold blue]{task.description}[/bold blue]"),
            BarColumn(bar_width=40, style="magenta", complete_style="bold #8D9FFF"),
            TaskProgressColumn(style="bold #8D9FFF"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        )
    with _progress_ctx as progress:
        if staged or hook_mode:
            task = progress.add_task("Scanning staged files...", total=None)
            findings = scanner.scan_staged()
            progress.update(task, completed=True)
        elif scan_all_flag:
            # --all: scan everything — working files (including untracked/gitignored) + history
            task1 = progress.add_task("Scanning all files on disk...", total=None)
            working = scanner.scan_working_directory(include_untracked=True)
            progress.update(task1, completed=True)
            task2 = progress.add_task("Scanning git history...", total=None)
            history_findings = scanner.scan_history()
            progress.update(task2, completed=True)
            working_keys = {(f.file, f.line) for f in working}
            history_only_count = sum(1 for f in history_findings if (f.file, f.line) not in working_keys)
            findings = scanner._dedupe_findings(history_findings + working)
            _scan_all_history_only_count = history_only_count
        elif history:
            task = progress.add_task("Scanning git history...", total=None)
            findings = scanner.scan_history()
            progress.update(task, completed=True)
        else:
            # Default smart scan: staged files + git history (ignores unstaged/untracked)
            task = progress.add_task("Scanning staged files + git history...", total=None)
            findings = scanner.scan_smart()
            progress.update(task, completed=True)

    # Show --all breakdown so users understand what history scanning added
    if scan_all_flag and findings:
        in_working = len(findings) - _scan_all_history_only_count
        if _scan_all_history_only_count > 0:
            console.print(
                f"[dim]--all: {in_working} secret(s) in working files + "
                f"{_scan_all_history_only_count} additional in history only "
                f"(removed from working files but still in git commits)[/dim]"
            )
        else:
            console.print(
                f"[dim]--all: {len(findings)} secret(s) — all present in both working files and git history. "
                f"Use `leakfix fix` to remove from both.[/dim]"
            )

    # Show warnings for skipped untracked files — only relevant in --all mode
    if scan_all_flag and scanner._untracked_files_warned:
        skipped_count = len(scanner._untracked_files_warned)
        if verbose:
            for f in sorted(scanner._untracked_files_warned):
                console.print(f"[dim]  Skipped {f} (untracked)[/dim]")
        else:
            console.print(f"[dim]{skipped_count} untracked file(s) scanned[/dim]")

    findings = _filter_by_severity(findings, severity)

    if hook_mode:
        # Check for dangerous files in staged files
        staged_files = HookManager.get_staged_files(repo_root)
        hook_mgr = HookManager(repo_root)
        dangerous_files = hook_mgr._check_dangerous_files(staged_files)
        if findings:
            config = load_config()
            llm_enabled = _check_llm_setup() if llm else config.get("llm_enabled", False)
            if llm_enabled:
                try:
                    import ollama  # noqa: F401
                except ImportError:
                    console.print(
                        "[yellow]ollama not installed. Run: pip install ollama[/yellow]"
                    )
                    llm_enabled = False
            classifier = Classifier(repo_root)
            classified = classifier.classify_findings(findings, llm_enabled)
            confirmed = [c for c in classified if c.classification == Classification.CONFIRMED]
            # Block on confirmed secrets OR dangerous files
            if confirmed or dangerous_files:
                _format_hook_mode(
                    [c.finding for c in confirmed],
                    dangerous_files,
                    path,
                )
                sys.exit(1)
        elif findings or dangerous_files:
            _format_hook_mode(findings, dangerous_files, path)
            sys.exit(1)
        console.print("🔍 leakfix pre-commit scan\n[green]✓ No secrets or dangerous files[/green]\n")
        sys.exit(0)

    if not findings:
        console.print("[green]No secrets found[/green]")
        if not scan_all_flag and not history:
            console.print(
                "[dim]Scanned staged files + git history. Run `leakfix scan --all` "
                "to also scan unstaged and untracked files.[/dim]"
            )
        sys.exit(0)
    config = load_config()
    llm_enabled = _check_llm_setup() if llm else config.get("llm_enabled", False)
    if llm_enabled:
        try:
            import ollama  # noqa: F401
        except ImportError:
            console.print(
                "[yellow]ollama not installed. Run: pip install ollama[/yellow]"
            )
            llm_enabled = False
    if smart and findings:
        classifier = Classifier(repo_root)
        # Classify with progress bar (Apple Intelligence glow style if available)
        if _UI_AVAILABLE:
            _pkwargs2 = glow_progress_kwargs()
            _columns2 = _pkwargs2.pop("columns", None)
            _classify_ctx = Progress(*_columns2, console=console, **_pkwargs2)
        else:
            _classify_ctx = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            )
        with _classify_ctx as progress:
            task = progress.add_task("Classifying findings...", total=len(findings))
            classified = []
            for finding in findings:
                result = classifier.classify_finding(finding, llm_enabled)
                classified.append(result)
                progress.advance(task)
        _format_smart_scan(classified, repo_root)
        # Exit 1 if any confirmed (real secrets)
        if any(c.classification == Classification.CONFIRMED for c in classified):
            sys.exit(1)
        sys.exit(0)

    if not findings:
        console.print("[green]No secrets found[/green]")
        if not scan_all_flag and not history:
            console.print(
                "[dim]Scanned staged files + git history. Run `leakfix scan --all` "
                "to also scan unstaged and untracked files.[/dim]"
            )
        sys.exit(0)

    if output == "table":
        _format_table(findings)
    elif output == "json":
        _format_json(findings)
    elif output == "html":
        report_path = Path(repo_root) / "leakfix-report.html"
        _format_html(findings, report_path)

    sys.exit(1)


@main.command()
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be replaced without making changes.",
)
@click.option(
    "--replace-with",
    default="",
    help="Custom replacement string (default: empty string).",
)
@click.option(
    "--no-push",
    is_flag=True,
    help="Fix locally but don't force push.",
)
@click.option(
    "--history-only",
    is_flag=True,
    help="Only rewrite history, don't touch working files.",
)
@click.option(
    "--files-only",
    is_flag=True,
    help="Only fix working files, don't touch history.",
)
@click.option(
    "--confirm",
    is_flag=True,
    help="Ask for confirmation before each replacement.",
)
@click.option(
    "--include-review",
    is_flag=True,
    help="Also fix REVIEW_NEEDED secrets (in addition to CONFIRMED).",
)
@click.option(
    "--llm",
    is_flag=True,
    help="Use LLM to classify REVIEW_NEEDED findings (requires ollama).",
)
@click.option(
    "--include-untracked",
    is_flag=True,
    help="Also scan and fix untracked files (files not in git). Use with caution.",
)
@click.option(
    "--all",
    "fix_all_flag",
    is_flag=True,
    help="Fix ALL findings including false positives (bypasses smart filtering).",
)
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
def fix(
    path: Path,
    dry_run: bool,
    replace_with: str,
    no_push: bool,
    history_only: bool,
    files_only: bool,
    confirm: bool,
    include_review: bool,
    llm: bool,
    include_untracked: bool,
    fix_all_flag: bool,
):
    """Fix/remove detected secrets in working files and git history."""
    if not check_gitleaks_installed():
        console.print("[red]gitleaks not found. Run: brew install gitleaks[/red]")
        sys.exit(2)

    if not check_git_filter_repo_installed() and not (dry_run or files_only):
        console.print(
            "[red]git-filter-repo not found. Run: brew install git-filter-repo[/red]"
        )
        sys.exit(2)

    if not is_git_repo(path):
        console.print("[red]Not a git repository. Run from a git repo or specify a path.[/red]")
        sys.exit(2)

    if history_only and files_only:
        console.print("[red]Cannot use --history-only and --files-only together.[/red]")
        sys.exit(2)

    config = load_config()
    llm_enabled = _check_llm_setup() if llm else config.get("llm_enabled", False)
    if llm_enabled:
        try:
            import ollama  # noqa: F401
        except ImportError:
            console.print(
                "[yellow]ollama not installed. Run: pip install ollama[/yellow]"
            )
            llm_enabled = False

    # Show warning for fix-all mode
    if fix_all_flag:
        console.print()
        console.print("[bold yellow]⚠️  --all mode: removing all findings including false positives[/bold yellow]")
        console.print("[dim]This will fix .env.example, README.md examples, template files, etc.[/dim]")

    # Show progress for fix operation (Apple Intelligence glow style if available)
    console.print()
    if _UI_AVAILABLE:
        from rich.progress import TextColumn as _TC, BarColumn as _BC, TimeElapsedColumn as _TE
        _fix_ctx = Progress(
            _TC(f"[bold {APPLE_BLUE_PURPLE}]{{task.description}}[/bold {APPLE_BLUE_PURPLE}]"),
            _BC(bar_width=40, style=APPLE_PURPLE, complete_style=APPLE_BLUE_PURPLE, finished_style=APPLE_PINK),
            _TE(),
            console=console,
            transient=False,
        )
    else:
        _fix_ctx = Progress(
            TextColumn("[bold blue]{task.description}[/bold blue]"),
            BarColumn(bar_width=40, style="magenta", complete_style="bold #8D9FFF"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )
    with _fix_ctx as progress:
        task1 = progress.add_task("Phase 1/3  Scanning for secrets...  ", total=1)
        fixer = Fixer(path)
        progress.update(task1, completed=1)
        task2 = progress.add_task("Phase 2/3  Fixing files...          ", total=1)
        task3 = progress.add_task("Phase 3/3  Rewriting git history... ", total=1)
        success, message = fixer.fix_all(
            dry_run=dry_run,
            replace_with=replace_with,
            no_push=no_push,
            history_only=history_only,
            files_only=files_only,
            confirm=confirm,
            include_review=include_review,
            llm_enabled=llm_enabled,
            include_untracked=include_untracked,
            fix_all_findings=fix_all_flag,
        )
        progress.update(task2, completed=1)
        progress.update(task3, completed=1)

    # Format output with new style
    if success:
        if _UI_AVAILABLE:
            print_success(message)
        else:
            if "secret(s) removed" in message:
                console.print(f"\n[green]✓ {message}[/green]")
            elif "No secrets found" in message or "No confirmed secrets" in message:
                console.print(f"\n[green]✓ {message}[/green]")
            else:
                console.print(f"\n[green]{message}[/green]")
        sys.exit(0)
    else:
        if _UI_AVAILABLE:
            print_error(message)
        else:
            console.print(f"\n[red]✗ {message}[/red]")
        sys.exit(1)


@main.command("install-hook")
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
def install_hook(path: Path):
    """Install pre-commit hook to prevent secret leaks."""
    if not is_git_repo(path):
        console.print("[red]Not a git repository. Run from a git repo or specify a path.[/red]")
        sys.exit(2)
    mgr = HookManager(path)
    if mgr.install_hook(smart=True):
        msg = f"[green]Pre-commit hook installed at {mgr.pre_commit_path}[/green]"
        msg += " [dim](smart mode: skips likely false positives)[/dim]"
        console.print(msg)
        sys.exit(0)
    console.print("[red]Failed to install hook[/red]")
    sys.exit(1)


@main.command("uninstall-hook")
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
def uninstall_hook(path: Path):
    """Uninstall pre-commit hook."""
    if not is_git_repo(path):
        console.print("[red]Not a git repository. Run from a git repo or specify a path.[/red]")
        sys.exit(2)
    mgr = HookManager(path)
    if mgr.uninstall_hook():
        console.print("[green]Pre-commit hook removed[/green]")
        sys.exit(0)
    console.print(
        "[yellow]Hook exists but was not installed by leakfix. Remove manually if desired.[/yellow]"
    )
    sys.exit(0)


@main.command("hook-status")
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
def hook_status(path: Path):
    """Check status of installed hooks."""
    if not is_git_repo(path):
        console.print("[red]Not a git repository. Run from a git repo or specify a path.[/red]")
        sys.exit(2)
    mgr = HookManager(path)
    status = mgr.get_hook_status()
    if status["installed"]:
        console.print("[green]Hook installed and active[/green]")
        console.print(f"  Path: {status['path']}")
    elif status["exists"] and not status["is_ours"]:
        console.print("[yellow]A pre-commit hook exists but was not installed by leakfix[/yellow]")
        console.print(f"  Path: {status['path']}")
    else:
        console.print("[dim]Hook not installed[/dim]")


@main.command()
@click.argument("value", type=str)
@click.option(
    "--file",
    "file_path",
    type=str,
    default=None,
    help="Optional file path for context (e.g. .env.example).",
)
@click.option(
    "--llm",
    is_flag=True,
    help="Use LLM to classify (requires ollama).",
)
def classify(value: str, file_path: str | None, llm: bool):
    """Manually check if a value is likely a false positive."""
    config = load_config()
    llm_enabled = _check_llm_setup() if llm else config.get("llm_enabled", False)
    if llm_enabled:
        try:
            import ollama  # noqa: F401
        except ImportError:
            console.print(
                "[yellow]ollama not installed. Run: pip install ollama[/yellow]"
            )
            llm_enabled = False
    classifier = Classifier()
    classification, reason = classifier.classify_value(value, file_path, llm_enabled)
    if "LLM classified" in reason or "LLM (context-aware):" in reason:
        loc = f"{file_path}:value" if file_path else "value"
        console.print(f"[#8D9FFF]LLM[/#8D9FFF]  {loc} → {_llm_display_name(classification)}")
    console.print(f"Classification: {classification.name}")
    console.print(f"Reason: {reason}")


def _format_org_summary(results: list[RepoResult]) -> None:
    """Print org scan summary with affected repos."""
    total = len(results)
    with_secrets = [r for r in results if r.findings]
    total_secrets = sum(len(r.findings) for r in results)

    console.print("\nSummary:")
    console.print(f"  Repos scanned: {total}")
    console.print(f"  Repos with secrets: {len(with_secrets)}")
    console.print(f"  Total secrets found: {total_secrets}")

    if with_secrets:
        console.print("\nAffected repositories:")
        for r in sorted(with_secrets, key=lambda x: -len(x.findings)):
            console.print(f"  [bold]📁 {r.repo_name}[/bold] ({len(r.findings)} secrets)")
        console.print("\nRun with --fix to auto-remediate all repositories.")


@main.command("scan-org")
@click.option(
    "--path",
    "path_arg",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Scan all git repos under this directory.",
)
@click.option(
    "--gitlab",
    type=str,
    default=None,
    help="GitLab base URL (e.g. https://gitlab.com). Use with --group.",
)
@click.option(
    "--github",
    is_flag=True,
    help="Scan GitHub organization. Use with --org.",
)
@click.option(
    "--token",
    type=str,
    default=None,
    envvar="GITLAB_TOKEN",
    help="API token for GitLab or GitHub (also GITLAB_TOKEN / GITHUB_TOKEN env).",
)
@click.option(
    "--group",
    type=str,
    default=None,
    help="GitLab group/namespace to scan (with --gitlab).",
)
@click.option(
    "--org",
    type=str,
    default=None,
    help="GitHub organization to scan (with --github).",
)
@click.option(
    "--fix",
    is_flag=True,
    help="Run leakfix fix on all affected repos after scan.",
)
@click.option(
    "--report",
    type=click.Path(path_type=Path),
    default=None,
    help="Write unified HTML report to this path.",
)
@click.option(
    "--exclude",
    type=str,
    default=None,
    help="Comma-separated repo names to exclude (e.g. repo1,repo2).",
)
@click.option(
    "--parallel",
    type=int,
    default=2,
    help="Number of parallel scans (default: 2).",
)
@click.option(
    "--no-push",
    is_flag=True,
    help="When used with --fix, fix locally but don't force push.",
)
@click.option(
    "--raw",
    "raw_flag",
    is_flag=True,
    help="Disable smart filtering, show all findings including false positives.",
)
@click.option(
    "--llm",
    is_flag=True,
    help="Use LLM to classify findings (requires ollama).",
)
@click.option(
    "--history",
    is_flag=True,
    help="Scan full git history in addition to working directory.",
)
def scan_org(
    path_arg: Path | None,
    gitlab: str | None,
    github: bool,
    token: str | None,
    group: str | None,
    org: str | None,
    fix: bool,
    report: Path | None,
    exclude: str | None,
    parallel: int,
    no_push: bool,
    raw_flag: bool,
    llm: bool,
    history: bool,
):
    """Scan organization repositories for secrets."""
    smart = not raw_flag
    
    if not check_gitleaks_installed():
        console.print("[red]gitleaks not found. Run: brew install gitleaks[/red]")
        sys.exit(2)

    # Resolve mode
    if path_arg is not None:
        mode = "directory"
    elif gitlab and group:
        mode = "gitlab"
        if not token:
            token = os.environ.get("GITLAB_TOKEN")
        if not token:
            console.print("[red]GitLab requires --token or GITLAB_TOKEN env[/red]")
            sys.exit(2)
    elif github and org:
        mode = "github"
        if not token:
            token = os.environ.get("GITHUB_TOKEN")
        if not token:
            console.print("[red]GitHub requires --token or GITHUB_TOKEN env[/red]")
            sys.exit(2)
    else:
        console.print(
            "[red]Specify one of: --path DIR, or --gitlab URL --group NAME, or --github --org NAME[/red]"
        )
        sys.exit(2)

    exclude_list = [x.strip() for x in (exclude or "").split(",") if x.strip()]

    scanner = OrgScanner()
    if mode == "directory":
        path_resolved = Path(path_arg).expanduser().resolve()
        results = scanner.scan_directory(
            path_resolved, exclude=exclude_list, parallel=parallel, smart=smart, scan_history=history
        )
    elif mode == "gitlab":
        results = scanner.scan_gitlab(
            gitlab, token, group, exclude=exclude_list, smart=smart, scan_history=history
        )
    else:
        results = scanner.scan_github(
            token, org, exclude=exclude_list, smart=smart, scan_history=history
        )

    if not results:
        console.print("[yellow]No repositories found to scan.[/yellow]")
        sys.exit(0)

    if report:
        scanner._generate_org_report(results, report)
        console.print(f"Report saved to [bold]{report}[/bold]")

    _format_org_summary(results)

    if fix:
        repos_with_secrets = [r for r in results if r.findings]
        if not repos_with_secrets:
            console.print("[green]No repos need fixing.[/green]")
            sys.exit(0)
        # Only fix directory-scanned repos (we have local paths)
        if mode != "directory":
            console.print(
                "[yellow]--fix only works with --path (local repos). "
                "GitLab/GitHub scans clone temporarily and cannot be fixed.[/yellow]"
            )
            sys.exit(1)
        fixed, errs = scanner.fix_all_repos(results, no_push=no_push)
        console.print(f"\n[green]Fixed {fixed} repo(s)[/green]")
        if errs:
            console.print(f"[yellow]{errs} repo(s) had errors[/yellow]")
        sys.exit(0 if errs == 0 else 1)

    total_secrets = sum(len(r.findings) for r in results)
    sys.exit(1 if total_secrets > 0 else 0)


@main.command()
@click.option(
    "--format",
    "-f",
    type=click.Choice(["html", "pdf", "json", "csv"]),
    default="html",
    help="Report format (default: html).",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Output file path.",
)
@click.option(
    "--since",
    type=str,
    default=None,
    help="Filter findings since date (YYYY-MM-DD).",
)
@click.option(
    "--author",
    type=str,
    default=None,
    help="Filter by commit author (substring match).",
)
@click.option(
    "--raw",
    "raw_flag",
    is_flag=True,
    help="Disable smart filtering, show all findings including false positives.",
)
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
def report(
    path: Path,
    format: str,
    output: Path | None,
    since: str | None,
    author: str | None,
    raw_flag: bool,
):
    """Generate report of detected secrets."""
    smart = not raw_flag
    
    if not check_gitleaks_installed():
        console.print("[red]gitleaks not found. Run: brew install gitleaks[/red]")
        sys.exit(2)
    if not is_git_repo(path):
        console.print("[red]Not a git repository.[/red]")
        sys.exit(2)
    try:
        reporter = Reporter(path)
        out_path = reporter.generate_report(
            format=format,
            output=output,
            since=since,
            author=author,
            smart=smart,
        )
        console.print(f"Report saved to [bold]{out_path}[/bold]")
        sys.exit(0)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(2)
    except ImportError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(2)


@main.group(invoke_without_command=True)
@click.pass_context
@click.option(
    "--daemon",
    is_flag=True,
    help="Run as background daemon.",
)
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, path_type=Path),
    default=".",
    help="Repository path to watch.",
)
def guard(ctx: click.Context, path: Path, daemon: bool):
    """Run guard/watch mode to prevent leaks."""
    from leakfix.watcher import Watcher, GUARD_PID_FILE

    if ctx.invoked_subcommand is not None:
        return

    if not is_git_repo(path):
        console.print("[red]Not a git repository.[/red]")
        sys.exit(2)

    watcher = Watcher(path)
    if daemon:
        try:
            watcher.start(daemon=True)
            console.print(f"[green]Guard started in daemon mode (PID file: {GUARD_PID_FILE})[/green]")
        except ImportError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(2)
    else:
        console.print("[dim]Watching for dangerous files... (Ctrl+C to stop)[/dim]")
        try:
            watcher.start(daemon=False)
        except ImportError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(2)
        except KeyboardInterrupt:
            pass


@guard.command("stop")
def guard_stop():
    """Stop the guard daemon."""
    from leakfix.watcher import Watcher

    watcher = Watcher()
    if watcher.stop():
        console.print("[green]Guard stopped[/green]")
        sys.exit(0)
    console.print("[yellow]Guard is not running[/yellow]")
    sys.exit(0)


@guard.command("status")
def guard_status():
    """Check if guard is running."""
    from leakfix.watcher import Watcher

    watcher = Watcher()
    status = watcher.status()
    if status.get("running"):
        console.print(f"[green]Guard is running (PID: {status.get('pid')})[/green]")
        sys.exit(0)
    console.print("[dim]Guard is not running[/dim]")
    sys.exit(0)


@main.command()
@click.option(
    "--generate",
    is_flag=True,
    help="Generate a security-focused .gitignore from scratch.",
)
@click.option(
    "--check",
    is_flag=True,
    help="Just check and report, don't modify.",
)
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
def gitignore(path: Path, generate: bool, check: bool):
    """Audit and fix .gitignore for secret-related patterns."""
    if not is_git_repo(path):
        console.print("[red]Not a git repository.[/red]")
        sys.exit(2)

    mgr = GitignoreManager(path)

    if generate:
        out = mgr.generate()
        console.print(f"[green]Generated .gitignore at {out}[/green]")
        sys.exit(0)

    if check:
        result = mgr.check()
        if result["missing"]:
            console.print(f"[yellow]Missing patterns in {result['path']}:[/yellow]")
            for p in result["missing"]:
                console.print(f"  - {p}")
            sys.exit(1)
        console.print("[green]All required patterns present[/green]")
        sys.exit(0)

    # Default: audit and fix
    result = mgr.audit()
    if result["added"]:
        console.print(f"[green]Added {len(result['added'])} pattern(s) to {result['path']}[/green]")
        for p in result["added"]:
            console.print(f"  + {p}")
        sys.exit(0)
    console.print("[green].gitignore already has all required patterns[/green]")
    sys.exit(0)
