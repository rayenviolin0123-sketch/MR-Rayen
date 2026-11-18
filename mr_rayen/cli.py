"""MR RAYEN command-line interface.

Usage:
  mr-rayen scan TARGET [--max-pages N] [--max-requests N] [--wordlist FILE] [--outdir DIR]
  mr-rayen dirs TARGET --wordlist FILE [--max-requests N] [--outdir DIR]
"""
from __future__ import annotations

import argparse
import os
import sys
import time

import requests

from . import __version__
from .analysis import AnalysisResult, analyze_response
from .discovery import Crawler
from .outputs import write_inventory_files
from .pathdiscovery import discover_paths
from .report import build_summary, write_html_report, write_json_report, write_txt_report

BANNER = r"""
╔══════════════════════════════════════════╗
║              MR  RAYEN                   ║
║  Authorized Web Recon & Hygiene Scanner  ║
╚══════════════════════════════════════════╝
"""

SCOPE_NOTICE = (
    "This tool is for systems you own or are explicitly authorized to test\n"
    "(owned systems, authorized pentests, permitted bug-bounty targets,\n"
    "CTF/lab environments). Never scan third-party targets without authorization.\n"
)


def _confirm_authorization(target: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    print(SCOPE_NOTICE)
    try:
        resp = input(f"Do you confirm you are authorized to test '{target}'? [y/N]: ").strip().lower()
    except EOFError:
        return False
    return resp in ("y", "yes")


def cmd_scan(args: argparse.Namespace) -> int:
    print(BANNER)
    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    if not _confirm_authorization(target, args.yes):
        print("Authorization not confirmed. Aborting.")
        return 1

    outdir = args.outdir
    reports_dir = os.path.join(outdir, "reports")
    results_dir = os.path.join(outdir, "results")
    os.makedirs(reports_dir, exist_ok=True)
    os.makedirs(results_dir, exist_ok=True)

    session = requests.Session()

    print(f"[*] Starting discovery on {target}")
    t0 = time.time()
    crawler = Crawler(
        target,
        max_pages=args.max_pages,
        max_requests=args.max_requests,
        delay=args.delay,
        session=session,
    )
    discovery = crawler.crawl()
    print(f"[+] Discovery complete: {len(discovery.url_store.unique_urls)} unique URLs, "
          f"{len(discovery.endpoints)} endpoints, {len(discovery.parameters)} parameters "
          f"({discovery.requests_made} requests, {time.time() - t0:.1f}s)")

    wordlist = None
    if args.wordlist:
        with open(args.wordlist, encoding="utf-8") as fh:
            wordlist = [line.strip() for line in fh if line.strip()]

    print("[*] Running path/file discovery")
    t0 = time.time()
    paths = discover_paths(
        target,
        wordlist=wordlist,
        max_requests=args.max_dir_requests,
        delay=args.delay,
        session=session,
    )
    print(f"[+] Path discovery complete: {len(paths.results)} paths checked "
          f"({paths.requests_made} requests, {time.time() - t0:.1f}s)")
    if paths.capped:
        print("[!] Path discovery stopped early: max_requests limit reached")

    print("[*] Analyzing responses for security hygiene issues")
    analysis = AnalysisResult()
    # Re-request each unique discovered page once for analysis (headers/body already
    # fetched during crawl are not retained per-response to keep memory small, so we
    # do a light second pass bounded by the same max_requests budget).
    analyzed = 0
    analysis_budget = max(0, args.max_requests - discovery.requests_made)
    for norm_url, original_url in list(discovery.url_store.all_urls.items())[:analysis_budget]:
        try:
            resp = session.get(original_url, timeout=10)
            analyze_response(original_url, resp, analysis)
            analyzed += 1
        except requests.RequestException:
            continue
    print(f"[+] Analysis complete: {analyzed} responses analyzed, {len(analysis.findings)} findings")

    write_inventory_files(results_dir, discovery, paths)

    summary = build_summary(target, discovery, analysis, paths)
    write_html_report(os.path.join(reports_dir, "report.html"), summary, discovery, analysis, paths)
    write_json_report(os.path.join(reports_dir, "report.json"), summary, discovery, analysis, paths)
    write_txt_report(os.path.join(reports_dir, "report.txt"), summary, discovery, analysis, paths)

    print()
    print("=" * 44)
    print("MR RAYEN SCAN SUMMARY".center(44))
    print("=" * 44)
    print(f"Target: {target}")
    print(f"Unique URLs: {summary['unique_urls']}   Endpoints: {summary['endpoints']}   "
          f"Parameters: {summary['parameters']}")
    print("Findings:", {k: v for k, v in summary["severity_counts"].items() if v})
    print()
    print(f"Reports written to: {os.path.abspath(reports_dir)}")
    print(f"Inventory files written to: {os.path.abspath(results_dir)}")
    print()
    print(summary["disclaimer"])
    return 0


def cmd_dirs(args: argparse.Namespace) -> int:
    print(BANNER)
    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    if not _confirm_authorization(target, args.yes):
        print("Authorization not confirmed. Aborting.")
        return 1

    wordlist = None
    if args.wordlist:
        with open(args.wordlist, encoding="utf-8") as fh:
            wordlist = [line.strip() for line in fh if line.strip()]

    print(f"[*] Running path discovery on {target} (max_requests={args.max_requests})")
    report = discover_paths(target, wordlist=wordlist, max_requests=args.max_requests, delay=args.delay)

    for r in report.results:
        status = r.status if r.status is not None else "ERR"
        extra = f" -> {r.redirect_to}" if r.redirect_to else ""
        print(f"[{status}] {r.url}{extra}")

    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)
        from .outputs import write_inventory_files  # noqa: avoid circular import issues
        with open(os.path.join(args.outdir, "directories.txt"), "w", encoding="utf-8") as fh:
            for r in report.results:
                status = r.status if r.status is not None else "ERR"
                fh.write(f"[{status}] {r.url}\n")
        print(f"\nResults written to {os.path.abspath(args.outdir)}/directories.txt")

    if report.capped:
        print("\n[!] Stopped early: max_requests limit reached")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mr-rayen", description="Authorized web recon & hygiene scanner")
    parser.add_argument("--version", action="version", version=f"mr-rayen {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Full discovery + hygiene-check scan")
    p_scan.add_argument("target", help="Target base URL or host, e.g. https://example.com")
    p_scan.add_argument("--max-pages", type=int, default=150, help="Max pages to crawl")
    p_scan.add_argument("--max-requests", type=int, default=400, help="Max total discovery+analysis requests")
    p_scan.add_argument("--max-dir-requests", type=int, default=300, help="Max requests for path discovery")
    p_scan.add_argument("--delay", type=float, default=0.1, help="Delay between requests (seconds)")
    p_scan.add_argument("--wordlist", help="Optional wordlist file for path discovery")
    p_scan.add_argument("--outdir", default="mr-rayen-output", help="Output directory")
    p_scan.add_argument("-y", "--yes", action="store_true", help="Skip interactive authorization confirmation")
    p_scan.set_defaults(func=cmd_scan)

    p_dirs = sub.add_parser("dirs", help="Path/file discovery only")
    p_dirs.add_argument("target", help="Target base URL or host")
    p_dirs.add_argument("--wordlist", help="Wordlist file of paths to check")
    p_dirs.add_argument("--max-requests", type=int, default=300)
    p_dirs.add_argument("--delay", type=float, default=0.15)
    p_dirs.add_argument("--outdir", help="Optional directory to write directories.txt into")
    p_dirs.add_argument("-y", "--yes", action="store_true", help="Skip interactive authorization confirmation")
    p_dirs.set_defaults(func=cmd_dirs)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
