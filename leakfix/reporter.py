"""Report generation for leakfix - HTML, PDF, JSON, CSV formats with filtering."""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from leakfix.classifier import Classification, Classifier, ClassifiedFinding
from leakfix.scanner import Finding, Scanner
from leakfix.utils import get_repo_root, is_git_repo


class Reporter:
    """Generate reports of secret findings in various formats."""

    def __init__(self, source: Path | str | None = None):
        self.source = Path(source or ".").resolve()
        self.repo_root = get_repo_root(self.source) or self.source

    def generate_report(
        self,
        format: str = "html",
        output: Path | str | None = None,
        since: str | None = None,
        author: str | None = None,
        smart: bool = False,
    ) -> Path:
        """Main entry point: scan, filter, and generate report."""
        if not is_git_repo(self.source):
            raise ValueError("Not a git repository")

        scanner = Scanner(self.source)
        findings = scanner.scan_history()

        if since:
            findings = self._filter_by_date(findings, since)
        if author:
            findings = self._filter_by_author(findings, author)

        # Always run classifier so classification column is populated in reports
        classified: list[ClassifiedFinding] | None = None
        if findings:
            classifier = Classifier(self.repo_root)
            classified = classifier.classify_findings(findings)
            if smart:
                # For smart mode, filter to only confirmed (or include all with classification)
                findings = [c.finding for c in classified]

        fmt = format.lower()
        if output is None:
            ext = {"html": ".html", "pdf": ".pdf", "json": ".json", "csv": ".csv"}.get(
                fmt, ".html"
            )
            output = self.repo_root / f"leakfix-report{ext}"
        output_path = Path(output).resolve()

        if fmt == "html":
            self._generate_html(findings, output_path, classified=classified)
        elif fmt == "pdf":
            self._generate_pdf(findings, output_path, classified=classified)
        elif fmt == "json":
            self._generate_json(findings, output_path, classified=classified)
        elif fmt == "csv":
            self._generate_csv(findings, output_path, classified=classified)
        else:
            raise ValueError(f"Unknown format: {format}")

        return output_path

    def _filter_by_date(self, findings: list[Finding], since: str) -> list[Finding]:
        """Filter findings by date (since YYYY-MM-DD)."""
        try:
            since_dt = datetime.strptime(since.strip(), "%Y-%m-%d")
        except ValueError:
            return findings
        result = []
        for f in findings:
            if not f.date:
                result.append(f)
                continue
            try:
                # gitleaks date format: "2024-01-15 10:30:00 +0000" or similar
                fd = f.date.split()[0]
                fd_dt = datetime.strptime(fd, "%Y-%m-%d")
                if fd_dt >= since_dt:
                    result.append(f)
            except (ValueError, IndexError):
                result.append(f)
        return result

    def _filter_by_author(self, findings: list[Finding], author: str) -> list[Finding]:
        """Filter findings by commit author (substring match)."""
        author_lower = author.lower()
        return [f for f in findings if author_lower in (f.author or "").lower()]

    def _calculate_risk_score(self, findings: list[Finding]) -> float:
        """Calculate risk score 0-100 based on severity and count."""
        if not findings:
            return 0.0
        weights = {"high": 3, "medium": 2, "low": 1}
        total = sum(weights.get(f.severity.lower(), 1) for f in findings)
        max_possible = len(findings) * 3
        return min(100.0, (total / max_possible) * 100) if max_possible else 0

    def _group_by_type(self, findings: list[Finding]) -> dict[str, list[Finding]]:
        """Group findings by secret type (rule_id)."""
        groups: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            groups[f.rule_id].append(f)
        return dict(groups)

    def _group_by_author(self, findings: list[Finding]) -> dict[str, list[Finding]]:
        """Group findings by author."""
        groups: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            key = f.author or "unknown"
            groups[key].append(f)
        return dict(groups)

    def _group_by_file(self, findings: list[Finding]) -> dict[str, list[Finding]]:
        """Group findings by file path."""
        groups: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            groups[f.file].append(f)
        return dict(groups)

    def _generate_html(
        self,
        findings: list[Finding],
        output: Path,
        classified: list[ClassifiedFinding] | None = None,
    ) -> None:
        """Generate HTML report with executive summary, charts, breakdowns."""
        risk_score = self._calculate_risk_score(findings)
        by_type = self._group_by_type(findings)
        by_file = self._group_by_file(findings)
        by_author = self._group_by_author(findings)
        repos_affected = len({f.file.split("/")[0] if "/" in f.file else f.file for f in findings})
        severity_counts = defaultdict(int)
        for f in findings:
            severity_counts[f.severity.lower()] += 1

        # Classification breakdown (when --smart)
        classification_counts: dict[str, int] = {}
        finding_to_class: dict[tuple[str, int, str], str] = {}
        if classified:
            for c in classified:
                classification_counts[c.classification.value] = (
                    classification_counts.get(c.classification.value, 0) + 1
                )
                key = (c.finding.file, c.finding.line, c.finding.rule_id)
                finding_to_class[key] = c.classification.value

        # Timeline: group by date
        by_date: dict[str, int] = defaultdict(int)
        for f in findings:
            if f.date:
                d = f.date.split()[0] if " " in f.date else f.date[:10]
                by_date[d] += 1
        timeline_items = sorted(by_date.items())

        # Build timeline chart (simple HTML bar chart)
        timeline_html = ""
        if timeline_items:
            max_count = max(c for _, c in timeline_items)
            for d, c in timeline_items:
                pct = (c / max_count * 100) if max_count else 0
                timeline_html += f'<div class="timeline-row"><span class="timeline-date">{d}</span><span class="timeline-bar" style="width:{pct}%"></span><span class="timeline-count">{c}</span></div>'

        # Breakdown by type
        type_rows = "".join(
            f"<tr><td>{k}</td><td>{len(v)}</td></tr>"
            for k, v in sorted(by_type.items(), key=lambda x: -len(x[1]))
        )

        # Breakdown by file
        file_rows = "".join(
            f"<tr><td>{k}</td><td>{len(v)}</td></tr>"
            for k, v in sorted(by_file.items(), key=lambda x: -len(x[1]))[:20]
        )

        # Breakdown by author
        author_rows = "".join(
            f"<tr><td>{k}</td><td>{len(v)}</td></tr>"
            for k, v in sorted(by_author.items(), key=lambda x: -len(x[1]))
        )

        # Table of all findings (with optional classification column)
        def _class_for_finding(f: Finding) -> str:
            if classified:
                key = (f.file, f.line, f.rule_id)
                return finding_to_class.get(key, "-")
            return "-"

        finding_rows = "".join(
            f"""<tr>
                <td>{_escape(f.file)}</td>
                <td>{_escape(f.rule_id)}</td>
                <td>{f.line}</td>
                <td>{f.severity.upper()}</td>
                <td>{_class_for_finding(f).upper()}</td>
                <td>{f.commit[:7] if len(f.commit) >= 7 else f.commit}</td>
                <td>{_escape(f.author or "-")}</td>
                <td>{_escape(f.date or "-")}</td>
            </tr>"""
            for f in findings
        )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>leakfix Security Report</title>
    <style>
        :root {{ --risk-high: #dc3545; --risk-medium: #fd7e14; --risk-low: #28a745; }}
        body {{ font-family: system-ui, -apple-system, sans-serif; margin: 2rem; max-width: 1200px; }}
        h1 {{ color: #333; border-bottom: 2px solid #333; padding-bottom: 0.5rem; }}
        h2 {{ color: #555; margin-top: 2rem; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin: 1.5rem 0; }}
        .summary-card {{ background: #f8f9fa; border-radius: 8px; padding: 1rem; border-left: 4px solid #333; }}
        .summary-card.high {{ border-color: var(--risk-high); }}
        .summary-card.medium {{ border-color: var(--risk-medium); }}
        .summary-card.low {{ border-color: var(--risk-low); }}
        .risk-score {{ font-size: 2rem; font-weight: bold; }}
        .risk-score.high {{ color: var(--risk-high); }}
        .risk-score.medium {{ color: var(--risk-medium); }}
        .risk-score.low {{ color: var(--risk-low); }}
        table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
        th {{ background: #333; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        .timeline {{ margin: 1rem 0; }}
        .timeline-row {{ display: flex; align-items: center; gap: 1rem; margin: 4px 0; }}
        .timeline-date {{ width: 100px; font-size: 0.9rem; }}
        .timeline-bar {{ height: 20px; background: #007bff; border-radius: 4px; min-width: 4px; }}
        .timeline-count {{ width: 40px; text-align: right; font-weight: 500; }}
        .meta {{ color: #666; font-size: 0.9rem; margin-bottom: 1rem; }}
    </style>
</head>
<body>
    <h1>leakfix Security Report</h1>
    <p class="meta">Generated {datetime.now().strftime("%Y-%m-%d %H:%M")} | Repository: {_escape(str(self.repo_root))}</p>

    <h2>Executive Summary</h2>
    <div class="summary">
        <div class="summary-card">
            <div>Total Secrets</div>
            <div class="risk-score">{len(findings)}</div>
        </div>
        <div class="summary-card">
            <div>Repos/Files Affected</div>
            <div class="risk-score">{repos_affected}</div>
        </div>
        <div class="summary-card high">
            <div>High Severity</div>
            <div class="risk-score high">{severity_counts.get("high", 0)}</div>
        </div>
        <div class="summary-card medium">
            <div>Medium Severity</div>
            <div class="risk-score medium">{severity_counts.get("medium", 0)}</div>
        </div>
        <div class="summary-card low">
            <div>Low Severity</div>
            <div class="risk-score low">{severity_counts.get("low", 0)}</div>
        </div>
        <div class="summary-card">
            <div>Risk Score</div>
            <div class="risk-score {'high' if risk_score >= 70 else 'medium' if risk_score >= 40 else 'low'}">{risk_score:.1f}/100</div>
        </div>
        {"".join(f'<div class="summary-card"><div>{k.replace("_", " ").title()}</div><div class="risk-score">{v}</div></div>' for k, v in classification_counts.items())}
    </div>

    <h2>Timeline</h2>
    <div class="timeline">
        {timeline_html if timeline_html else "<p>No date data available.</p>"}
    </div>

    <h2>Breakdown by Secret Type</h2>
    <table>
        <thead><tr><th>Type</th><th>Count</th></tr></thead>
        <tbody>{type_rows}</tbody>
    </table>

    <h2>Breakdown by File</h2>
    <table>
        <thead><tr><th>File</th><th>Count</th></tr></thead>
        <tbody>{file_rows}</tbody>
    </table>

    <h2>Breakdown by Author</h2>
    <table>
        <thead><tr><th>Author</th><th>Count</th></tr></thead>
        <tbody>{author_rows}</tbody>
    </table>

    <h2>All Findings</h2>
    <table>
        <thead>
            <tr>
                <th>File</th>
                <th>Secret Type</th>
                <th>Line</th>
                <th>Severity</th>
                <th>Classification</th>
                <th>Commit</th>
                <th>Author</th>
                <th>Date</th>
            </tr>
        </thead>
        <tbody>{finding_rows}</tbody>
    </table>
</body>
</html>"""
        output.write_text(html, encoding="utf-8")

    def _generate_pdf(
        self,
        findings: list[Finding],
        output: Path,
        classified: list[ClassifiedFinding] | None = None,
    ) -> None:
        """Generate PDF report using playwright headless chromium."""
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise ImportError(
                "playwright is required for PDF generation. "
                "Install it with: pip install 'leakfix[pdf]' && playwright install chromium"
            )

        # Generate HTML first to temp file, then convert to PDF
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            self._generate_html(findings, tmp_path, classified=classified)
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page()
                page.goto(f"file://{tmp_path.resolve()}")
                page.pdf(path=str(output), format="A4", print_background=True)
                browser.close()
        finally:
            tmp_path.unlink(missing_ok=True)

    def _generate_json(
        self,
        findings: list[Finding],
        output: Path,
        classified: list[ClassifiedFinding] | None = None,
    ) -> None:
        """Generate JSON report."""
        risk_score = self._calculate_risk_score(findings)
        by_type = {k: len(v) for k, v in self._group_by_type(findings).items()}
        by_file = {k: len(v) for k, v in self._group_by_file(findings).items()}
        by_author = {k: len(v) for k, v in self._group_by_author(findings).items()}
        severity_counts = defaultdict(int)
        for f in findings:
            severity_counts[f.severity.lower()] += 1

        finding_to_class: dict[tuple[str, int, str], str] = {}
        if classified:
            for c in classified:
                key = (c.finding.file, c.finding.line, c.finding.rule_id)
                finding_to_class[key] = c.classification.value

        findings_data = []
        for f in findings:
            d = asdict(f)
            # Never store full secret in reports - mask for security
            d["secret_value"] = f.secret_value[:7] + "***" if len(f.secret_value) > 10 else "***"
            if classified:
                key = (f.file, f.line, f.rule_id)
                d["classification"] = finding_to_class.get(key, "")
            findings_data.append(d)

        summary: dict = {
            "total_secrets": len(findings),
            "repos_affected": len(by_file),
            "risk_score": risk_score,
            "severity": dict(severity_counts),
        }
        if classified:
            classification_counts: dict[str, int] = {}
            for c in classified:
                classification_counts[c.classification.value] = (
                    classification_counts.get(c.classification.value, 0) + 1
                )
            summary["classification"] = classification_counts

        report = {
            "summary": summary,
            "by_type": by_type,
            "by_file": by_file,
            "by_author": by_author,
            "findings": findings_data,
        }
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")

    def _generate_csv(
        self,
        findings: list[Finding],
        output: Path,
        classified: list[ClassifiedFinding] | None = None,
    ) -> None:
        """Generate CSV report for spreadsheet import."""
        finding_to_class: dict[tuple[str, int, str], str] = {}
        if classified:
            for c in classified:
                key = (c.finding.file, c.finding.line, c.finding.rule_id)
                finding_to_class[key] = c.classification.value

        headers = ["file", "rule_id", "line", "commit", "author", "date", "severity", "entropy"]
        if classified:
            headers.append("classification")
        # Never include secret_value in CSV - security
        if not findings:
            output.write_text(",".join(headers) + "\n", encoding="utf-8")
            return
        with output.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for finding in findings:
                # Never include secret_value in CSV - security
                row = [
                    finding.file,
                    finding.rule_id,
                    finding.line,
                    finding.commit,
                    finding.author or "",
                    finding.date or "",
                    finding.severity,
                    finding.entropy,
                ]
                if classified:
                    key = (finding.file, finding.line, finding.rule_id)
                    row.append(finding_to_class.get(key, ""))
                writer.writerow(row)


def _escape(s: str) -> str:
    """Escape HTML entities."""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
