"""
MR RAYEN — Authorized Web Reconnaissance & Security Hygiene Scanner
=====================================================================

Scope and intent
-----------------
This tool performs PASSIVE, NON-INTRUSIVE reconnaissance and configuration
hygiene checks against a web target. It is meant for use only against:

  - systems you own
  - targets you have explicit written authorization to test
  - bug-bounty programs where this kind of testing is permitted
  - local/lab/CTF environments

What this tool does:
  - Crawls and discovers URLs, endpoints, forms, and JS-referenced paths
  - Normalizes and deduplicates discovered URLs
  - Builds an endpoint and parameter inventory
  - Detects technology (server, frameworks, generators, JS libraries)
  - Checks for the *presence/absence* of security headers and cookie flags
  - Checks CORS header configuration
  - Checks for the existence of commonly-referenced files
    (robots.txt, sitemap.xml, security.txt, swagger.json, etc.) —
    existence and metadata only, never contents of anything sensitive
  - Flags verbose error pages that a target exposes on its own
    (e.g. a framework debug page returned for a normal, unmodified request)
  - Produces HTML/JSON/TXT reports

What this tool deliberately does NOT do:
  - It does not send SQL injection, XSS, or any other attack payloads
  - It does not attempt to bypass authentication or access controls
  - It does not brute force directories beyond an explicit, rate-limited
    wordlist the user supplies
  - It does not extract, dump, or guess database contents
  - It does not exploit anything it finds

This is a reconnaissance and hygiene-checking tool, not a vulnerability
exploitation tool.
"""

__version__ = "0.1.0"
