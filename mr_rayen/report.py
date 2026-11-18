"""Report generation: HTML, JSON, and plain-text summaries."""
from __future__ import annotations

import html as html_escape
import json
from dataclasses import asdict
from datetime import datetime, timezone

from .analysis import AnalysisResult, Finding
from .discovery import DiscoveryResult
from .pathdiscovery import PathDiscoveryReport

DISCLAIMER = (
    "No vulnerability scanner can guarantee that a website is secure. "
    "MR RAYEN reports findings based on the evidence and security checks "
    "implemented in the current version."
)

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_COLORS = {
    "CRITICAL": "#7f1d1d",
    "HIGH": "#b91c1c",
    "MEDIUM": "#b45309",
    "LOW": "#1d4ed8",
    "INFO": "#4b5563",
}


def build_summary(
    target: str,
    discovery: DiscoveryResult,
    analysis: AnalysisResult,
    paths: PathDiscoveryReport,
) -> dict:
    severity_counts = {s: 0 for s in SEVERITY_ORDER}
    category_counts: dict[str, int] = {}
    for f in analysis.findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    return {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "urls_discovered": len(discovery.url_store.all_urls) + len(discovery.url_store.skipped),
        "unique_urls": len(discovery.url_store.unique_urls),
        "parameterized_urls": len(discovery.url_store.parameterized_urls),
        "static_urls": len(discovery.url_store.static_urls),
        "endpoints": len(discovery.endpoints),
        "parameters": len(discovery.parameters),
        "js_files": len(discovery.js_files),
        "directories_tested": len(paths.results),
        "requests": {
            "discovery": discovery.requests_made,
            "path_discovery": paths.requests_made,
        },
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "disclaimer": DISCLAIMER,
    }


def write_json_report(path: str, summary: dict, discovery: DiscoveryResult,
                       analysis: AnalysisResult, paths: PathDiscoveryReport) -> None:
    data = {
        "summary": summary,
        "technologies": sorted(analysis.technologies),
        "findings": [asdict(f) for f in analysis.findings],
        "skipped_urls": [asdict(s) for s in discovery.url_store.skipped],
        "path_results": [asdict(p) for p in paths.results],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)


def write_txt_report(path: str, summary: dict, discovery: DiscoveryResult,
                      analysis: AnalysisResult, paths: PathDiscoveryReport) -> None:
    lines = []
    lines.append("=" * 60)
    lines.append("MR RAYEN SCAN SUMMARY".center(60))
    lines.append("=" * 60)
    lines.append(f"Target: {summary['target']}")
    lines.append(f"Generated: {summary['generated_at']}")
    lines.append("")
    lines.append(f"URLs discovered:     {summary['urls_discovered']}")
    lines.append(f"Unique URLs:         {summary['unique_urls']}")
    lines.append(f"Parameterized URLs:  {summary['parameterized_urls']}")
    lines.append(f"Static URLs:         {summary['static_urls']}")
    lines.append(f"Endpoints:           {summary['endpoints']}")
    lines.append(f"Parameters:          {summary['parameters']}")
    lines.append(f"JavaScript files:    {summary['js_files']}")
    lines.append(f"Directories tested:  {summary['directories_tested']}")
    lines.append("")
    lines.append("Requests:")
    lines.append(f"  Discovery:         {summary['requests']['discovery']}")
    lines.append(f"  Path discovery:    {summary['requests']['path_discovery']}")
    lines.append("")
    lines.append("Findings by severity:")
    for sev in SEVERITY_ORDER:
        lines.append(f"  {sev:<10} {summary['severity_counts'].get(sev, 0)}")
    lines.append("")
    lines.append("Findings by category:")
    for cat, count in sorted(summary["category_counts"].items()):
        lines.append(f"  {cat:<25} {count}")
    lines.append("")
    lines.append("Technologies detected:")
    for tech in sorted(analysis.technologies):
        lines.append(f"  - {tech}")
    lines.append("")
    lines.append("-" * 60)
    lines.append("FINDINGS")
    lines.append("-" * 60)
    for f in sorted(analysis.findings, key=lambda x: SEVERITY_ORDER.index(x.severity)):
        lines.append(f"[{f.severity}] {f.title}")
        lines.append(f"  URL: {f.url}")
        lines.append(f"  Evidence: {f.evidence}")
        if f.recommendation:
            lines.append(f"  Recommendation: {f.recommendation}")
        if f.cwe:
            lines.append(f"  CWE: {f.cwe}")
        lines.append("")
    lines.append("-" * 60)
    lines.append(summary["disclaimer"])

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def write_html_report(path: str, summary: dict, discovery: DiscoveryResult,
                       analysis: AnalysisResult, paths: PathDiscoveryReport) -> None:
    def esc(s) -> str:
        return html_escape.escape(str(s))

    findings_sorted = sorted(analysis.findings, key=lambda x: SEVERITY_ORDER.index(x.severity))

    rows = []
    for f in findings_sorted:
        color = SEVERITY_COLORS.get(f.severity, "#4b5563")
        rows.append(f"""
        <tr>
          <td><span class="badge" style="background:{color}">{esc(f.severity)}</span></td>
          <td>{esc(f.category)}</td>
          <td>{esc(f.title)}</td>
          <td><code>{esc(f.url)}</code></td>
          <td>{esc(f.evidence)}</td>
          <td>{esc(f.cwe or '')}</td>
        </tr>""")

    sev_cards = "".join(
        f'<div class="card"><div class="num" style="color:{SEVERITY_COLORS[s]}">'
        f'{summary["severity_counts"].get(s, 0)}</div><div class="label">{s}</div></div>'
        for s in SEVERITY_ORDER
    )

    tech_list = "".join(f"<li>{esc(t)}</li>" for t in sorted(analysis.technologies)) or "<li>None detected</li>"

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MR RAYEN Report — {esc(summary['target'])}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin:0; padding:2rem;
         background:#0b0f14; color:#e5e7eb; }}
  h1 {{ font-size:1.4rem; margin-bottom:0.2rem; }}
  .sub {{ color:#9ca3af; margin-bottom:1.5rem; }}
  .grid {{ display:flex; gap:0.75rem; flex-wrap:wrap; margin-bottom:2rem; }}
  .card {{ background:#131a22; border:1px solid #1f2937; border-radius:10px;
          padding:1rem 1.25rem; min-width:90px; text-align:center; }}
  .num {{ font-size:1.6rem; font-weight:700; }}
  .label {{ font-size:0.75rem; color:#9ca3af; letter-spacing:0.05em; }}
  table {{ width:100%; border-collapse:collapse; margin-top:1rem; font-size:0.85rem; }}
  th, td {{ text-align:left; padding:0.5rem 0.6rem; border-bottom:1px solid #1f2937; vertical-align:top; }}
  th {{ color:#9ca3af; font-weight:600; font-size:0.75rem; text-transform:uppercase; }}
  code {{ word-break:break-all; color:#93c5fd; }}
  .badge {{ color:white; padding:2px 8px; border-radius:6px; font-size:0.7rem; font-weight:700; }}
  .section {{ margin-top:2.5rem; }}
  .disclaimer {{ margin-top:2.5rem; padding:1rem; background:#1f2937; border-radius:8px; font-size:0.85rem; color:#d1d5db; }}
  ul.tech {{ columns:2; font-size:0.9rem; }}
</style>
</head>
<body>
  <h1>MR RAYEN Scan Report</h1>
  <div class="sub">Target: {esc(summary['target'])} &middot; Generated: {esc(summary['generated_at'])}</div>

  <div class="grid">{sev_cards}</div>

  <div class="section">
    <h2>Scan Statistics</h2>
    <table>
      <tr><td>URLs discovered</td><td>{summary['urls_discovered']}</td></tr>
      <tr><td>Unique URLs</td><td>{summary['unique_urls']}</td></tr>
      <tr><td>Parameterized URLs</td><td>{summary['parameterized_urls']}</td></tr>
      <tr><td>Static URLs</td><td>{summary['static_urls']}</td></tr>
      <tr><td>Endpoints</td><td>{summary['endpoints']}</td></tr>
      <tr><td>Parameters</td><td>{summary['parameters']}</td></tr>
      <tr><td>JavaScript files</td><td>{summary['js_files']}</td></tr>
      <tr><td>Directories/files tested</td><td>{summary['directories_tested']}</td></tr>
    </table>
  </div>

  <div class="section">
    <h2>Technologies Detected</h2>
    <ul class="tech">{tech_list}</ul>
  </div>

  <div class="section">
    <h2>Findings</h2>
    <table>
      <thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>URL</th><th>Evidence</th><th>CWE</th></tr></thead>
      <tbody>{''.join(rows) if rows else '<tr><td colspan="6">No findings.</td></tr>'}</tbody>
    </table>
  </div>

  <div class="disclaimer">{esc(summary['disclaimer'])}</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
