::: {align="center"}
# 🛡️ MR RAYEN

### Authorized Web Recon & Security Hygiene Scanner

**Passive • Non-Intrusive • Evidence-Based • Authorization-First**

[![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-See%20Repository-lightgrey)](#license)
[![Security](https://img.shields.io/badge/Security-Passive%20Recon-00B8D9)](#security-model)
[![Status](https://img.shields.io/badge/Status-Active-2EA44F)](#project-status)
:::

```{=html}
<p align="center">
```
`<img src="banner.png" alt="MR RAYEN — Authorized Web Recon & Security Hygiene Scanner" width="100%">`{=html}
```{=html}
</p>
```

------------------------------------------------------------------------

## 📌 Overview

**MR RAYEN** is a passive, non-intrusive web reconnaissance and
configuration-hygiene scanner designed for **authorized security
testing**.

It discovers URLs, endpoints, parameters, technologies, and referenced
resources, then checks security-related configuration such as HTTP
security headers, cookies, and CORS behavior.

The tool generates structured **HTML, JSON, and TXT reports** so
findings can be reviewed, shared, and used as a starting point for
manual security assessment.

> **MR RAYEN is a reconnaissance and security-hygiene tool, not an
> exploitation framework.**

------------------------------------------------------------------------

## ⚡ What It Does

  -----------------------------------------------------------------------
  Area                                Capability
  ----------------------------------- -----------------------------------
  🌐 Web Recon                        Crawls and discovers URLs, links,
                                      forms, and JS-referenced paths

  🗺️ Site Metadata                    Parses `robots.txt` and
                                      `sitemap.xml`

  🔗 URL Processing                   Normalizes and deduplicates
                                      discovered URLs

  🎯 Endpoint Inventory               Builds endpoint and parameter
                                      inventories

  🧩 Technology Detection             Detects servers, frameworks,
                                      generator tags, and common JS
                                      libraries

  🛡️ Security Headers                 Checks CSP, HSTS, X-Frame-Options,
                                      and other security headers

  🍪 Cookie Security                  Checks `Secure`, `HttpOnly`, and
                                      `SameSite` flags

  🔄 CORS                             Checks CORS headers for risky
                                      configuration combinations

  📄 Common Files                     Checks existence and metadata of
                                      referenced files such as
                                      `security.txt` and `swagger.json`

  🚨 Error Exposure                   Flags verbose error/debug pages and
                                      masks secret-looking values

  📊 Reporting                        Generates HTML, JSON, and TXT
                                      reports
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 🚫 Security Boundaries

MR RAYEN deliberately avoids offensive exploitation.

It **does not** perform:

-   SQL injection payloads
-   XSS payloads
-   Authentication bypass attempts
-   Access-control bypass attempts
-   Credential extraction
-   Database dumping
-   Exploitation of vulnerabilities
-   Unbounded brute forcing

Path discovery is intentionally capped by `--max-dir-requests` and uses
only a small built-in list plus an optional user-provided wordlist.

------------------------------------------------------------------------

## 🔐 Authorization

Use MR RAYEN only against:

-   systems you own
-   systems where you have explicit written authorization
-   bug-bounty programs where this type of testing is permitted
-   local laboratories and CTF environments

The CLI asks for authorization before scanning.

For automation or CI environments, the authorization confirmation can be
skipped with:

``` bash
-y
```

or:

``` bash
--yes
```

> **You are responsible for ensuring that you have permission to test
> the target.**

------------------------------------------------------------------------

## 🧰 Installation

### 1. Clone the repository

``` bash
git clone https://github.com/YOUR_USERNAME/mr-rayen.git
cd mr-rayen
```

### 2. Install dependencies

``` bash
pip install -r requirements.txt
```

### Requirements

MR RAYEN currently uses:

-   Python 3.x
-   `requests`
-   `beautifulsoup4`

------------------------------------------------------------------------

## 🚀 Usage

### Full scan

``` bash
python3 -m mr_rayen.cli scan https://example.com \
    --max-pages 150 \
    --max-requests 400 \
    --max-dir-requests 300 \
    --delay 0.1 \
    --wordlist paths.txt \
    --outdir mr-rayen-output
```

### Path / file discovery only

``` bash
python3 -m mr_rayen.cli dirs \
    https://example.com \
    --wordlist paths.txt \
    --max-requests 300
```

### CI / non-interactive authorization

If you are authorized to test the target:

``` bash
python3 -m mr_rayen.cli scan https://example.com -y
```

------------------------------------------------------------------------

## 📁 Output

A scan produces an output directory similar to:

``` text
mr-rayen-output/
├── reports/
│   ├── report.html
│   ├── report.json
│   └── report.txt
│
└── results/
    ├── urls.txt
    ├── urls_unique.txt
    ├── urls_with_parameters.txt
    ├── endpoints.txt
    ├── parameters.txt
    ├── directories.txt
    └── skipped.txt
```

### Report formats

**HTML**

Human-readable report for reviewing scan results in a browser.

**JSON**

Structured output suitable for automation, processing, and integration
with other tools.

**TXT**

Simple text report for terminals, logs, and quick review.

------------------------------------------------------------------------

## 🔎 Reconnaissance Workflow

``` text
                 ┌─────────────────┐
                 │ Authorized      │
                 │ Target          │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │ URL / Link      │
                 │ Discovery       │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │ Normalize &     │
                 │ Deduplicate     │
                 └────────┬────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
     Endpoints       Technologies      Resources
          │               │               │
          └───────────────┼───────────────┘
                          ▼
                 ┌─────────────────┐
                 │ Security        │
                 │ Hygiene Checks  │
                 └────────┬────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
       Headers          Cookies          CORS
          │               │               │
          └───────────────┼───────────────┘
                          ▼
                 ┌─────────────────┐
                 │ Evidence &      │
                 │ Findings        │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │ HTML / JSON /    │
                 │ TXT Reports      │
                 └─────────────────┘
```

------------------------------------------------------------------------

## 🧪 Example

``` bash
python3 -m mr_rayen.cli scan https://example.com \
    --max-pages 150 \
    --max-requests 400 \
    --max-dir-requests 300 \
    --delay 0.1 \
    --outdir mr-rayen-output
```

The scanner first requests authorization confirmation, then performs
bounded reconnaissance and hygiene checks.

------------------------------------------------------------------------

## 🛡️ Security Model

MR RAYEN follows a **passive-first** approach.

The scanner focuses on information and configuration that the target
already exposes through normal web behavior.

It does not attempt to prove exploitability by sending attack payloads.

### Examples of evidence collected

``` text
URL discovered
        ↓
Endpoint identified
        ↓
Technology fingerprinted
        ↓
Security header observed
        ↓
Cookie attributes inspected
        ↓
CORS configuration observed
        ↓
Finding recorded
        ↓
Report generated
```

This makes the tool useful for:

-   security hygiene reviews
-   reconnaissance
-   asset inventory
-   defensive development
-   authorized bug-bounty reconnaissance
-   local security labs
-   learning web-security fundamentals

------------------------------------------------------------------------

## 📊 Findings Philosophy

A reported item should be treated as **evidence from the implemented
checks**, not as a guarantee that a system is vulnerable.

For example:

``` text
Missing security header
        ≠
Confirmed exploitable vulnerability
```

MR RAYEN reports what it can observe and verify through its implemented
checks. Further manual assessment may be required to determine
real-world impact.

------------------------------------------------------------------------

## 🧱 Project Structure

A typical project layout is:

``` text
mr-rayen/
├── mr_rayen/
│   ├── cli.py
│   └── ...
│
├── reports/
├── results/
├── requirements.txt
├── paths.txt
└── README.md
```

The exact internal module layout may evolve as the project develops.

------------------------------------------------------------------------

## 🖥️ GitHub Presentation

Recommended repository assets:

``` text
.github/
└── ...

assets/
└── banner.png

mr_rayen/
├── cli.py
└── ...

README.md
requirements.txt
paths.txt
```

Place the generated project banner at:

``` text
assets/banner.png
```

and update the image reference in this README to:

``` markdown
<img src="assets/banner.png" alt="MR RAYEN" width="100%">
```

------------------------------------------------------------------------

## 🗺️ Roadmap

Possible future improvements:

-   [ ] More technology fingerprints
-   [ ] Additional passive security checks
-   [ ] Improved HTML report design
-   [ ] Configurable scan profiles
-   [ ] Better CI integration
-   [ ] More automated tests
-   [ ] Export improvements
-   [ ] Additional documentation and examples

------------------------------------------------------------------------

## ⚠️ Limitations

No automated scanner can guarantee that a website is secure.

MR RAYEN reports findings based on the evidence and checks implemented
in the current version.

It is **not a replacement for a complete manual security assessment**.

------------------------------------------------------------------------

## 📜 License

Add the project's chosen license here before publishing.

For example:

``` text
MIT License
```

if the repository is intended to be released under MIT.

------------------------------------------------------------------------

## 👤 Author

**MR RAYEN**

Security research • Web reconnaissance • Defensive tooling

------------------------------------------------------------------------

## ⭐ Contributing

Contributions, bug reports, improvements, and documentation updates are
welcome when they preserve the project's authorization-first and
non-exploitative design.

Before submitting changes:

1.  Keep scans bounded.
2.  Avoid adding exploitation payloads.
3.  Preserve authorization checks.
4.  Document new security checks.
5.  Add tests where appropriate.

------------------------------------------------------------------------

::: {align="center"}
### 🔎 Discover. Analyze. Document.

**MR RAYEN --- Authorized Web Recon & Security Hygiene Scanner**
:::
