"""Organization-wide scanning - scans multiple repositories across an organization."""

from __future__ import annotations

import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import requests
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from leakfix.classifier import Classification, Classifier
from leakfix.scanner import Finding, Scanner

console = Console()


@dataclass
class RepoResult:
    """Result of scanning a single repository."""

    repo_path: str
    repo_name: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


class OrgScanner:
    """Scans multiple repositories for secrets - directory, GitLab, or GitHub."""

    def __init__(self):
        self.results: list[RepoResult] = []

    def scan_directory(
        self,
        path: Path | str,
        exclude: list[str] | None = None,
        parallel: int = 2,
        smart: bool = False,
    ) -> list[RepoResult]:
        """Scan all git repos under a directory."""
        path = Path(path).resolve()
        if not path.exists():
            return []
        exclude_set = set((exclude or []))
        repos = self._find_git_repos(path)
        repos = [r for r in repos if Path(r).name not in exclude_set]
        return self._scan_repos_parallel(repos, parallel, smart=smart)

    def scan_gitlab(
        self,
        url: str,
        token: str,
        group: str,
        exclude: list[str] | None = None,
        smart: bool = False,
    ) -> list[RepoResult]:
        """Scan all repos in a GitLab group by cloning temporarily."""
        exclude_set = set((exclude or []))
        repo_urls = self._list_gitlab_repos(url, token, group)
        repo_urls = [(u, n) for u, n in repo_urls if n not in exclude_set]
        return self._scan_cloned_repos(repo_urls, smart=smart)

    def scan_github(
        self,
        token: str,
        org: str,
        exclude: list[str] | None = None,
        smart: bool = False,
    ) -> list[RepoResult]:
        """Scan all repos in a GitHub org by cloning temporarily."""
        exclude_set = set((exclude or []))
        repo_urls = self._list_github_repos(token, org)
        repo_urls = [(u, n) for u, n in repo_urls if n not in exclude_set]
        return self._scan_cloned_repos(repo_urls, smart=smart)

    def _find_git_repos(self, path: Path) -> list[Path]:
        """Recursively find all git repos under a directory."""
        repos: list[Path] = []
        path = Path(path).resolve()
        if not path.is_dir():
            return []
        for entry in path.iterdir():
            if entry.name.startswith("."):
                continue
            git_dir = entry / ".git"
            if git_dir.exists() and git_dir.is_dir():
                repos.append(entry)
            elif entry.is_dir():
                repos.extend(self._find_git_repos(entry))
        return repos

    def _scan_repo(self, repo_path: Path, smart: bool = False) -> RepoResult:
        """Scan a single repo and return RepoResult."""
        repo_path = Path(repo_path).resolve()
        repo_name = repo_path.name
        try:
            scanner = Scanner(repo_path)
            findings = scanner.scan_all()
            if smart and findings:
                classifier = Classifier(repo_path)
                classified = classifier.classify_findings(findings)
                findings = [
                    c.finding
                    for c in classified
                    if c.classification == Classification.CONFIRMED
                ]
            return RepoResult(
                repo_path=str(repo_path),
                repo_name=repo_name,
                findings=findings,
                error=None,
            )
        except Exception as e:
            return RepoResult(
                repo_path=str(repo_path),
                repo_name=repo_name,
                findings=[],
                error=str(e),
            )

    def _scan_repos_parallel(
        self,
        repo_paths: list[Path],
        parallel: int,
        smart: bool = False,
    ) -> list[RepoResult]:
        """Scan multiple repos in parallel with progress bar."""
        results: list[RepoResult] = []
        total = len(repo_paths)
        if total == 0:
            return results

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                "Scanning organization repositories...",
                total=total,
            )
            with ThreadPoolExecutor(max_workers=parallel) as executor:
                future_to_repo = {
                    executor.submit(self._scan_repo, p, smart): p for p in repo_paths
                }
                for future in as_completed(future_to_repo):
                    repo_path = future_to_repo[future]
                    result = future.result()
                    results.append(result)
                    progress.update(
                        task,
                        advance=1,
                        description=f"Scanning... {repo_path.name}",
                    )
        return results

    def _list_gitlab_repos(self, base_url: str, token: str, group: str) -> list[tuple[str, str]]:
        """List all project clone URLs in a GitLab group."""
        base_url = base_url.rstrip("/")
        api_url = f"{base_url}/api/v4"
        group_encoded = requests.utils.quote(group, safe="")
        url = f"{api_url}/groups/{group_encoded}/projects"
        headers = {"PRIVATE-TOKEN": token}
        repos: list[tuple[str, str]] = []
        page = 1
        while True:
            resp = requests.get(
                url,
                headers=headers,
                params={"per_page": 100, "page": page, "include_subgroups": "true"},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            if not data:
                break
            for proj in data:
                http_url = proj.get("http_url_to_repo") or proj.get("web_url", "").replace(
                    ".git", ""
                )
                if not http_url.endswith(".git"):
                    http_url += ".git"
                # Add token for private repos
                if token and "https://" in http_url:
                    parsed = urlparse(http_url)
                    http_url = f"{parsed.scheme}://oauth2:{token}@{parsed.netloc}{parsed.path}"
                name = proj.get("path") or proj.get("name", "")
                repos.append((http_url, name))
            if len(data) < 100:
                break
            page += 1
        return repos

    def _list_github_repos(self, token: str, org: str) -> list[tuple[str, str]]:
        """List all repo clone URLs in a GitHub org."""
        url = f"https://api.github.com/orgs/{org}/repos"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        repos: list[tuple[str, str]] = []
        page = 1
        while True:
            resp = requests.get(
                url,
                headers=headers,
                params={"per_page": 100, "page": page, "type": "all"},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            if not data:
                break
            for repo in data:
                clone_url = repo.get("clone_url") or repo.get("html_url", "").replace(
                    "github.com/", "github.com/"
                )
                if not clone_url.endswith(".git"):
                    clone_url += ".git"
                if token:
                    clone_url = clone_url.replace(
                        "https://",
                        f"https://{token}@",
                        1,
                    )
                name = repo.get("name", "")
                repos.append((clone_url, name))
            if len(data) < 100:
                break
            page += 1
        return repos

    def _clone_repo(self, url: str, temp_dir: Path) -> Path | None:
        """Clone a repo into temp_dir. Returns path to cloned repo or None."""
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", url, str(temp_dir)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                return None
            return temp_dir
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            return None

    def _scan_cloned_repos(
        self,
        repo_urls: list[tuple[str, str]],
        smart: bool = False,
    ) -> list[RepoResult]:
        """Clone each repo, scan it, then clean up."""
        results: list[RepoResult] = []
        total = len(repo_urls)
        if total == 0:
            return results

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                "Scanning organization repositories...",
                total=total,
            )
            for url, name in repo_urls:
                with tempfile.TemporaryDirectory(prefix="leakfix-org-") as tmp:
                    clone_path = Path(tmp) / name
                    clone_path.mkdir(parents=True, exist_ok=True)
                    cloned = self._clone_repo(url, clone_path)
                    if cloned:
                        result = self._scan_repo(cloned, smart=smart)
                        result.repo_name = name
                        result.repo_path = url
                        results.append(result)
                    else:
                        results.append(
                            RepoResult(
                                repo_path=url,
                                repo_name=name,
                                findings=[],
                                error="Failed to clone",
                            )
                        )
                progress.update(task, advance=1)
        return results

    def _aggregate_results(self, results: list[RepoResult]) -> dict:
        """Combine all results into summary stats."""
        total_repos = len(results)
        repos_with_secrets = sum(1 for r in results if r.findings)
        total_secrets = sum(len(r.findings) for r in results)
        return {
            "total_repos": total_repos,
            "repos_with_secrets": repos_with_secrets,
            "total_secrets": total_secrets,
            "results": results,
        }

    def _generate_org_report(
        self,
        results: list[RepoResult],
        output_path: Path | str,
    ) -> None:
        """Generate unified HTML report across all repos."""
        output_path = Path(output_path)
        agg = self._aggregate_results(results)
        total_repos = agg["total_repos"]
        repos_with_secrets = agg["repos_with_secrets"]
        total_secrets = agg["total_secrets"]

        sections: list[str] = []
        for r in results:
            if not r.findings:
                continue
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
                for f in r.findings
            )
            sections.append(
                f"""
            <h3>{r.repo_name} ({len(r.findings)} secrets)</h3>
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
            </table>"""
            )

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Organization Security Scan Report</title>
    <style>
        body {{ font-family: system-ui, sans-serif; margin: 2rem; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #333; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        h2 {{ margin-top: 2rem; }}
        h3 {{ margin-top: 1.5rem; color: #555; }}
    </style>
</head>
<body>
    <h1>Organization Security Scan Report</h1>
    <h2>Summary</h2>
    <p>{total_repos} repos scanned, {repos_with_secrets} with secrets, {total_secrets} total secrets</p>

    <h2>Findings by Repository</h2>
    {"".join(sections) if sections else "<p>No secrets found.</p>"}
</body>
</html>"""
        output_path.write_text(html)

    def fix_all_repos(
        self,
        results: list[RepoResult],
        no_push: bool = False,
    ) -> tuple[int, int]:
        """Run fix on all affected repos. Returns (fixed_count, error_count)."""
        from leakfix.fixer import Fixer

        fixed = 0
        errors = 0
        for r in results:
            if not r.findings:
                continue
            repo_path = Path(r.repo_path)
            if not repo_path.exists():
                # Was a cloned URL - we can't fix those
                errors += 1
                continue
            try:
                fixer = Fixer(repo_path)
                success, _ = fixer.fix_all(no_push=no_push)
                if success:
                    fixed += 1
                else:
                    errors += 1
            except Exception:
                errors += 1
        return fixed, errors
