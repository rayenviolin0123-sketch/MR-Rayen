"""Writes the plain-text inventory files (urls.txt, endpoints.txt, etc.)."""
from __future__ import annotations

import os

from .discovery import DiscoveryResult
from .pathdiscovery import PathDiscoveryReport


def write_inventory_files(outdir: str, discovery: DiscoveryResult, paths: PathDiscoveryReport) -> None:
    os.makedirs(outdir, exist_ok=True)

    with open(os.path.join(outdir, "urls.txt"), "w", encoding="utf-8") as fh:
        for norm, original in discovery.url_store.all_urls.items():
            fh.write(f"{original}\n")

    with open(os.path.join(outdir, "urls_unique.txt"), "w", encoding="utf-8") as fh:
        for norm in discovery.url_store.unique_urls:
            fh.write(f"{norm}\n")

    with open(os.path.join(outdir, "urls_with_parameters.txt"), "w", encoding="utf-8") as fh:
        for norm in discovery.url_store.parameterized_urls:
            fh.write(f"{norm}\n")

    with open(os.path.join(outdir, "endpoints.txt"), "w", encoding="utf-8") as fh:
        for method, path in sorted(discovery.endpoints):
            fh.write(f"{method:<6} {path}\n")

    with open(os.path.join(outdir, "parameters.txt"), "w", encoding="utf-8") as fh:
        seen = set()
        for p in discovery.parameters:
            key = (p.endpoint, p.method, p.name)
            if key in seen:
                continue
            seen.add(key)
            fh.write(
                f"Endpoint: {p.endpoint}\n"
                f"Parameter: {p.name}\n"
                f"Method: {p.method}\n"
                f"Source: {p.source}\n"
                f"Confidence: {p.confidence}\n\n"
            )

    with open(os.path.join(outdir, "directories.txt"), "w", encoding="utf-8") as fh:
        for r in paths.results:
            status = r.status if r.status is not None else "ERR"
            fh.write(f"[{status}] {r.url}\n")

    with open(os.path.join(outdir, "skipped.txt"), "w", encoding="utf-8") as fh:
        for s in discovery.url_store.skipped:
            fh.write(f"{s.url}  ({s.reason})\n")
