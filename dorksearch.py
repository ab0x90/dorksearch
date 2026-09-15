#!/usr/bin/env python3
"""
dorksearch — Google dorking + GitHub code search for OSINT and pentest recon.

Google dorking requires: pip install googlesearch-python
  Without it the tool prints clickable dork URLs instead of live results.

GitHub search requires a personal access token (--github-token).
  Token needs no special scopes for public repo search.
  Add 'repo' scope to also search private repos your account can access.

Usage:
  python3 dorksearch.py example.com
  python3 dorksearch.py example.com --github-token ghp_xxx
  python3 dorksearch.py example.com --github-org acme-corp --github-token ghp_xxx
  python3 dorksearch.py example.com --dorks-only
  python3 dorksearch.py example.com --no-google --github-org acme --github-token ghp_xxx
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import quote_plus

import requests
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich import box as rbox
from rich.text import Text

try:
    from googlesearch import search as _google_search
    GOOGLE_AVAILABLE = True
except ImportError:
    GOOGLE_AVAILABLE = False

BANNER = "[bold cyan]dorksearch[/]  [dim]·  Google dorking + GitHub code search[/]"
console = Console()

GITHUB_API = "https://api.github.com"
GOOGLE_BASE = "https://www.google.com/search?q="

# ── Dork definitions ──────────────────────────────────────────────────────────
# Each entry: (description, severity, dork_template)
# {target} → target domain, e.g. example.com

DORK_CATEGORIES: dict[str, list[tuple[str, str, str]]] = {
    "admin": [
        ("Admin panel",            "MEDIUM",   "site:{target} inurl:admin"),
        ("Login page",             "LOW",      "site:{target} inurl:login"),
        ("WordPress admin",        "MEDIUM",   "site:{target} inurl:wp-admin"),
        ("cPanel",                 "MEDIUM",   "site:{target} inurl:cpanel"),
        ("phpMyAdmin",             "HIGH",     "site:{target} inurl:phpmyadmin"),
        ("Webmail",                "LOW",      "site:{target} inurl:webmail"),
        ("Remote access",          "MEDIUM",   "site:{target} inurl:remote"),
        ("VPN portal",             "MEDIUM",   "site:{target} inurl:vpn"),
        ("Citrix portal",          "MEDIUM",   'site:{target} inurl:citrix OR inurl:"Citrix"'),
    ],
    "files": [
        (".env files",             "CRITICAL", "site:{target} ext:env"),
        ("SQL dumps",              "CRITICAL", "site:{target} ext:sql"),
        ("Log files",              "HIGH",     "site:{target} ext:log"),
        ("Backup files",           "HIGH",     "site:{target} ext:bak OR ext:backup"),
        ("Config files",           "HIGH",     "site:{target} ext:conf OR ext:config"),
        ("YAML/YML configs",       "HIGH",     "site:{target} ext:yaml OR ext:yml"),
        ("INI files",              "MEDIUM",   "site:{target} ext:ini"),
        ("XML configs",            "MEDIUM",   "site:{target} ext:xml inurl:config"),
        ("PHP source",             "MEDIUM",   "site:{target} ext:php intitle:phpinfo"),
        ("Private key files",      "CRITICAL", "site:{target} ext:pem OR ext:key"),
        ("Shell scripts",          "LOW",      "site:{target} ext:sh"),
    ],
    "listings": [
        ("Directory listing",      "HIGH",     'site:{target} intitle:"index of"'),
        ("FTP listing",            "HIGH",     'site:{target} intitle:"index of /" inurl:ftp'),
        ("Open directory",         "MEDIUM",   'site:{target} intitle:"directory listing"'),
    ],
    "docs": [
        ("Exposed PDFs",           "LOW",      "site:{target} ext:pdf"),
        ("Word documents",         "LOW",      "site:{target} ext:docx OR ext:doc"),
        ("Spreadsheets",           "MEDIUM",   "site:{target} ext:xlsx OR ext:xls OR ext:csv"),
        ("Presentations",          "LOW",      "site:{target} ext:pptx OR ext:ppt"),
        ("Confidential docs",      "HIGH",     'site:{target} "confidential" ext:pdf'),
        ("Internal docs",          "HIGH",     'site:{target} "internal use only"'),
        ("Network diagrams",       "MEDIUM",   "site:{target} ext:vsd OR ext:vsdx"),
    ],
    "errors": [
        ("MySQL errors",           "HIGH",     'site:{target} "Warning: mysql_fetch"'),
        ("MySQL errors (alt)",     "HIGH",     'site:{target} "MySQL Error"'),
        ("Oracle errors",          "HIGH",     'site:{target} "ORA-" error'),
        ("PHP warnings",           "MEDIUM",   'site:{target} "PHP Warning"'),
        ("Stack traces",           "MEDIUM",   'site:{target} "stack trace"'),
        ("ASP.NET errors",         "MEDIUM",   'site:{target} "Server Error in" "Application"'),
        ("Python tracebacks",      "MEDIUM",   'site:{target} "Traceback (most recent call"'),
        ("JDBC exceptions",        "HIGH",     'site:{target} "java.sql.SQLException"'),
    ],
    "cloud": [
        ("S3 buckets",             "HIGH",     'site:s3.amazonaws.com "{target}"'),
        ("Google Cloud Storage",   "HIGH",     'site:storage.googleapis.com "{target}"'),
        ("Azure Blob",             "HIGH",     'site:blob.core.windows.net "{target}"'),
        ("DigitalOcean Spaces",    "MEDIUM",   'site:digitaloceanspaces.com "{target}"'),
    ],
    "repos": [
        ("GitHub references",      "MEDIUM",   'site:github.com "{target}"'),
        ("GitLab references",      "MEDIUM",   'site:gitlab.com "{target}"'),
        ("Pastebin leaks",         "HIGH",     'site:pastebin.com "{target}"'),
        ("Gists",                  "MEDIUM",   'site:gist.github.com "{target}"'),
        ("Trello boards",          "MEDIUM",   'site:trello.com "{target}"'),
        ("Postman collections",    "MEDIUM",   'site:postman.com "{target}"'),
    ],
    "creds": [
        ("Passwords in pages",     "HIGH",     'site:{target} intext:password'),
        ("API keys in pages",      "HIGH",     'site:{target} intext:"api key"'),
        ("Tokens in pages",        "HIGH",     'site:{target} intext:"access token"'),
        ("Credentials in URLs",    "HIGH",     'site:{target} inurl:password'),
        ("Default creds page",     "MEDIUM",   'site:{target} "default password"'),
    ],
    "subdomains": [
        ("Subdomain enumeration",  "INFO",     "site:*.{target}"),
    ],
}

# ── GitHub search query definitions ──────────────────────────────────────────
# (description, severity, query_template)
# {target} → domain, {org} → org name, {user} → user name

GITHUB_DOMAIN_QUERIES: list[tuple[str, str, str]] = [
    ("Private RSA keys",           "CRITICAL", '"{target}" "BEGIN RSA PRIVATE KEY"'),
    ("Private keys (PKCS8)",       "CRITICAL", '"{target}" "BEGIN PRIVATE KEY"'),
    ("Private EC keys",            "CRITICAL", '"{target}" "BEGIN EC PRIVATE KEY"'),
    ("AWS access keys",            "CRITICAL", '"{target}" "AKIA"'),
    ("Hardcoded passwords",        "HIGH",     '"{target}" password'),
    ("API keys",                   "HIGH",     '"{target}" api_key'),
    ("API secrets",                "HIGH",     '"{target}" api_secret'),
    ("Access tokens",              "HIGH",     '"{target}" access_token'),
    ("Bearer tokens",              "HIGH",     '"{target}" "Bearer"'),
    ("Database URLs",              "HIGH",     '"{target}" "DATABASE_URL"'),
    ("JDBC connection strings",    "HIGH",     '"{target}" "jdbc:mysql" OR "jdbc:postgresql"'),
    ("MongoDB connection strings", "HIGH",     '"{target}" "mongodb://"'),
    (".env file references",       "HIGH",     '"{target}" filename:.env'),
    ("Slack tokens",               "HIGH",     '"{target}" "xoxb-" OR "xoxp-"'),
    ("SendGrid keys",              "HIGH",     '"{target}" "SG."'),
    ("Stripe keys",                "HIGH",     '"{target}" "sk_live_"'),
    ("Twilio credentials",         "HIGH",     '"{target}" "TWILIO_ACCOUNT_SID"'),
    ("Generic secrets",            "MEDIUM",   '"{target}" secret'),
    ("Config files",               "MEDIUM",   '"{target}" filename:config.yml OR filename:config.json'),
]

GITHUB_ORG_QUERIES: list[tuple[str, str, str]] = [
    ("Private RSA keys",           "CRITICAL", '"BEGIN RSA PRIVATE KEY" org:{scope}'),
    ("Private keys (PKCS8)",       "CRITICAL", '"BEGIN PRIVATE KEY" org:{scope}'),
    ("Private EC keys",            "CRITICAL", '"BEGIN EC PRIVATE KEY" org:{scope}'),
    ("AWS access keys",            "CRITICAL", '"AKIA" org:{scope}'),
    ("Hardcoded passwords",        "HIGH",     'password org:{scope} filename:*.env OR filename:*.yml OR filename:*.json'),
    ("API keys in org",            "HIGH",     'api_key org:{scope}'),
    ("Database URLs",              "HIGH",     '"DATABASE_URL" org:{scope}'),
    ("Secret keys",                "HIGH",     '"SECRET_KEY" org:{scope}'),
    ("Private keys in configs",    "HIGH",     '"private_key" org:{scope}'),
    ("Stripe live keys",           "CRITICAL", '"sk_live_" org:{scope}'),
    ("Slack tokens",               "HIGH",     '"xoxb-" org:{scope}'),
    (".env files",                 "HIGH",     'filename:.env org:{scope}'),
    ("Password files",             "HIGH",     'filename:passwords.txt OR filename:credentials.txt org:{scope}'),
    ("SSH private keys",           "CRITICAL", 'filename:id_rsa org:{scope}'),
    ("SSH private keys (ed25519)", "CRITICAL", 'filename:id_ed25519 org:{scope}'),
    ("JWT secrets",                "HIGH",     '"JWT_SECRET" OR "jwt_secret" org:{scope}'),
    ("Connection strings",         "HIGH",     '"connection string" org:{scope}'),
    ("S3 credentials",             "HIGH",     '"AWS_SECRET_ACCESS_KEY" org:{scope}'),
    ("GCP credentials",            "HIGH",     'filename:service_account.json org:{scope}'),
    ("Internal IPs in configs",    "LOW",      '"192.168." OR "10.0." filename:*.env OR filename:*.yml org:{scope}'),
]

GITHUB_USER_QUERIES: list[tuple[str, str, str]] = [
    # Same as org but uses user:{scope}
    (desc, sev, q.replace("org:{scope}", "user:{scope}"))
    for desc, sev, q in GITHUB_ORG_QUERIES
]

# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class Result:
    source: str      # "google" or "github"
    category: str
    description: str
    severity: str
    url: str
    detail: str = ""  # matching snippet, file path, etc.

# ── Google dorking ────────────────────────────────────────────────────────────

def dork_url(dork: str) -> str:
    return GOOGLE_BASE + quote_plus(dork)

def run_google_dorks(
    target: str,
    categories: list[str],
    max_results: int,
    delay: float,
    dorks_only: bool,
) -> list[Result]:
    results: list[Result] = []

    all_dorks: list[tuple[str, str, str, str]] = []  # (category, desc, sev, dork)
    for cat in categories:
        for desc, sev, template in DORK_CATEGORIES.get(cat, []):
            dork = template.replace("{target}", target)
            all_dorks.append((cat, desc, sev, dork))

    if dorks_only or not GOOGLE_AVAILABLE:
        mode = "URL-only (install googlesearch-python for live scraping)" if not GOOGLE_AVAILABLE and not dorks_only else "URL-only mode"
        console.print(f"  [dim]→ Google: {mode}[/]")
        for cat, desc, sev, dork in all_dorks:
            results.append(Result(
                source="google", category=cat, description=desc,
                severity=sev, url=dork_url(dork), detail=dork,
            ))
        return results

    console.print(f"  [dim]→ Google: live scraping {len(all_dorks)} dorks (delay: {delay}s)...[/]")
    for i, (cat, desc, sev, dork) in enumerate(all_dorks, 1):
        console.print(f"  [dim]  [{i}/{len(all_dorks)}] {desc}...[/]", end="\r")
        try:
            urls = list(_google_search(dork, num_results=max_results, sleep_interval=0, lang="en"))
            for u in urls:
                results.append(Result(
                    source="google", category=cat, description=desc,
                    severity=sev, url=u, detail=dork,
                ))
            if urls:
                console.print(f"  [green]  [{i}/{len(all_dorks)}] {desc}: {len(urls)} result(s)[/]")
        except Exception as e:
            console.print(f"  [yellow]  [{i}/{len(all_dorks)}] {desc}: {e}[/]")
        time.sleep(delay)

    console.print()
    return results

# ── GitHub search ─────────────────────────────────────────────────────────────

@dataclass
class GithubResult:
    description: str
    severity: str
    repo: str
    path: str
    url: str
    snippet: str = ""

def _gh_search(query: str, token: str, max_results: int) -> list[dict]:
    """Single GitHub code search API call. Returns raw items."""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.text-match+json",
    }
    params = {"q": query, "per_page": min(max_results, 100)}
    try:
        r = requests.get(f"{GITHUB_API}/search/code", headers=headers, params=params, timeout=15)
        if r.status_code == 401:
            console.print("  [red]GitHub: 401 Unauthorized — check your token[/]")
            return []
        if r.status_code == 403:
            reset = r.headers.get("X-RateLimit-Reset", "")
            console.print(f"  [yellow]GitHub: rate limited (resets: {reset})[/]")
            return []
        if r.status_code == 422:
            console.print(f"  [dim]GitHub: query rejected (422) — {query[:60]}[/]")
            return []
        if not r.ok:
            console.print(f"  [yellow]GitHub: HTTP {r.status_code} for query: {query[:60]}[/]")
            return []
        return r.json().get("items", [])
    except requests.RequestException as e:
        console.print(f"  [yellow]GitHub request error: {e}[/]")
        return []

def _extract_snippet(item: dict) -> str:
    """Pull first text match fragment from the API response."""
    matches = item.get("text_matches", [])
    if matches:
        fragment = matches[0].get("fragment", "")
        return fragment.strip().replace("\n", " ")[:200]
    return ""

def run_github_search(
    target: str,
    token: str,
    org: str,
    user: str,
    search_terms: list[str],
    max_results: int,
    delay: float,
) -> list[GithubResult]:
    results: list[GithubResult] = []
    query_sets: list[tuple[str, str, str]] = []

    # Domain-referenced queries — only run when at least one explicit search term
    # is given. Firing the bare root domain returns too many unrelated results.
    if search_terms:
        for term in search_terms:
            for desc, sev, template in GITHUB_DOMAIN_QUERIES:
                label = f"{desc} [{term}]" if len(search_terms) > 1 else desc
                query_sets.append((label, sev, template.replace("{target}", term)))
    elif not org and not user:
        # Token provided but nothing to narrow the search — warn and skip domain queries.
        console.print(
            "  [yellow]→ GitHub: skipping domain queries — root domain is too broad.[/]\n"
            "  [dim]    Add --github-search \"@domain.com\" or --github-org ORG to target results.[/]\n"
        )

    # Org-scoped queries
    if org:
        for desc, sev, template in GITHUB_ORG_QUERIES:
            query_sets.append((desc, sev, template.replace("{scope}", org)))

    # User-scoped queries
    if user:
        for desc, sev, template in GITHUB_USER_QUERIES:
            query_sets.append((desc, sev, template.replace("{scope}", user)))

    if not query_sets:
        return results

    total = len(query_sets)
    scope_parts = []
    if search_terms:
        scope_parts.append("terms: " + ", ".join(f'"{t}"' for t in search_terms))
    if org:
        scope_parts.append(f"org: {org}")
    if user:
        scope_parts.append(f"user: {user}")
    console.print(f"  [dim]→ GitHub: {total} quer{'y' if total == 1 else 'ies'}"
                  f"{' (' + ', '.join(scope_parts) + ')' if scope_parts else ''}...[/]")

    seen_urls: set[str] = set()

    for i, (desc, sev, query) in enumerate(query_sets, 1):
        console.print(f"  [dim]  [{i}/{total}] {desc}...[/]", end="\r")
        items = _gh_search(query, token, max_results)
        new = 0
        for item in items:
            url = item.get("html_url", "")
            if url in seen_urls:
                continue
            seen_urls.add(url)
            results.append(GithubResult(
                description=desc,
                severity=sev,
                repo=item.get("repository", {}).get("full_name", ""),
                path=item.get("path", ""),
                url=url,
                snippet=_extract_snippet(item),
            ))
            new += 1
        if new:
            console.print(f"  [{'red' if sev == 'CRITICAL' else 'orange3' if sev == 'HIGH' else 'yellow'}]  [{i}/{total}] {desc}: {new} result(s)[/]")
        time.sleep(delay)

    console.print()
    return results

# ── Rich output ───────────────────────────────────────────────────────────────

SEV_COLOR = {
    "CRITICAL": "red",
    "HIGH":     "orange3",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
}

def _badge(sev: str) -> str:
    color = SEV_COLOR.get(sev, "white")
    return f"[{color}][{sev:8}][/]"

def print_header(target: str, org: str, user: str, search_terms: list[str]):
    console.print()
    console.print(Panel(BANNER, expand=False, border_style="cyan dim"))
    console.print(f"\n  [bold]target    [/] : [cyan]{target}[/]")
    if search_terms:
        console.print(f"  [bold]gh search [/] : [cyan]{', '.join(search_terms)}[/]")
    if org:
        console.print(f"  [bold]gh org    [/] : [cyan]{org}[/]")
    if user:
        console.print(f"  [bold]gh user   [/] : [cyan]{user}[/]")
    console.print()

def print_google_results(results: list[Result], dorks_only: bool):
    if not results:
        return
    console.print(Rule(" Google Dork Results ", style="dim"))
    console.print()

    if dorks_only or not GOOGLE_AVAILABLE:
        label = "Dork URLs" if dorks_only else "Dork URLs (install googlesearch-python for live results)"
        console.print(f"  [dim]{label}[/]\n")

    # Group by severity then category
    by_sev: dict[str, list[Result]] = {}
    for r in results:
        by_sev.setdefault(r.severity, []).append(r)

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        group = by_sev.get(sev, [])
        if not group:
            continue
        for r in group:
            console.print(f"  {_badge(r.severity)}  [bold]{r.description}[/]")
            if dorks_only or not GOOGLE_AVAILABLE:
                console.print(f"             [dim]{r.detail}[/]")
                console.print(f"             [cyan underline]{r.url}[/]")
            else:
                console.print(f"             [cyan underline]{r.url}[/]")
    console.print()

def print_github_results(results: list[GithubResult]):
    if not results:
        console.print(Rule(" GitHub Results ", style="dim"))
        console.print("\n  [dim]No results found.[/]\n")
        return

    console.print(Rule(" GitHub Results ", style="dim"))
    console.print()

    # Table grouped by severity
    t = Table(box=rbox.SIMPLE_HEAD, show_header=True,
              header_style="bold dim", padding=(0, 1), expand=True)
    t.add_column("Sev",    width=10,  no_wrap=True)
    t.add_column("Finding",           no_wrap=True)
    t.add_column("Repo / Path",       no_wrap=False)
    t.add_column("URL",               no_wrap=False)

    by_sev: dict[str, list[GithubResult]] = {}
    for r in results:
        by_sev.setdefault(r.severity, []).append(r)

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        for r in by_sev.get(sev, []):
            color = SEV_COLOR.get(sev, "white")
            t.add_row(
                f"[{color}]{sev}[/]",
                r.description,
                f"{r.repo}\n[dim]{r.path}[/]",
                f"[cyan underline]{r.url}[/]",
            )

    console.print(t)

    # Print snippets for CRITICAL/HIGH findings
    crit_high = [r for r in results if r.severity in ("CRITICAL", "HIGH") and r.snippet]
    if crit_high:
        console.print(Rule(" Critical / High Snippets ", style="dim"))
        console.print()
        for r in crit_high[:20]:  # cap at 20 to avoid wall of text
            console.print(f"  {_badge(r.severity)}  [bold]{r.description}[/]  [dim]{r.repo}/{r.path}[/]")
            console.print(f"  [dim]  …{r.snippet}…[/]")
            console.print(f"  [cyan underline]  {r.url}[/]\n")

def print_summary(google: list[Result], github: list[GithubResult]):
    console.print(Rule(" Summary ", style="dim"))
    console.print()

    counts: dict[str, int] = {}
    for r in google:
        counts[r.severity] = counts.get(r.severity, 0) + 1
    for r in github:
        counts[r.severity] = counts.get(r.severity, 0) + 1

    total = sum(counts.values())
    console.print(f"  Total results : [bold]{total}[/]")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = counts.get(sev, 0)
        if n:
            color = SEV_COLOR[sev]
            console.print(f"  [{color}]{sev:10}[/] : {n}")
    console.print()

# ── Export ────────────────────────────────────────────────────────────────────

def export_json(
    target: str,
    google: list[Result],
    github: list[GithubResult],
    path: str,
):
    out = {
        "target": target,
        "google": [
            {"severity": r.severity, "category": r.category,
             "description": r.description, "url": r.url, "dork": r.detail}
            for r in google
        ],
        "github": [
            {"severity": r.severity, "description": r.description,
             "repo": r.repo, "path": r.path, "url": r.url, "snippet": r.snippet}
            for r in github
        ],
    }
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    console.print(f"  [dim]Results saved to {path}[/]\n")

# ── Entry point ───────────────────────────────────────────────────────────────

ALL_CATEGORIES = list(DORK_CATEGORIES.keys())

def main():
    parser = argparse.ArgumentParser(
        prog="dorksearch",
        description="Google dorking + GitHub code search for pentest recon.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python3 dorksearch.py example.com --dorks-only\n"
            "  python3 dorksearch.py example.com --github-token ghp_xxx --github-search \"@example.com\"\n"
            "  python3 dorksearch.py example.com --github-token ghp_xxx --github-org acme\n"
            "  python3 dorksearch.py example.com --github-token ghp_xxx \\\n"
            "      --github-search \"@example.com,acme-internal\" --github-org acme\n"
            "  python3 dorksearch.py example.com --no-google --github-token ghp_xxx \\\n"
            "      --github-search \"@example.com\" --github-org acme --output results.json\n"
        ),
    )
    parser.add_argument("target",
                        help="Target domain (e.g. example.com)")
    parser.add_argument("--github-token", metavar="TOKEN",
                        help="GitHub personal access token")
    parser.add_argument("--github-org", metavar="ORG",
                        help="Scope GitHub search to this organization")
    parser.add_argument("--github-user", metavar="USER",
                        help="Scope GitHub search to this user")
    parser.add_argument("--github-search", metavar="TERM[,TERM]",
                        help="Search term(s) for GitHub domain queries — replaces the raw "
                             "target domain. Comma-separate for multiple terms. "
                             "Examples: \"@example.com\", \"acme-internal\", "
                             "\"@example.com,acme-corp\". Without this flag and without "
                             "--github-org/--github-user, domain queries are skipped "
                             "because the bare domain returns too many unrelated results.")
    parser.add_argument("--categories", metavar="LIST",
                        help=f"Comma-separated dork categories "
                             f"(default: all). Available: {', '.join(ALL_CATEGORIES)}")
    parser.add_argument("--dorks-only", action="store_true",
                        help="Print dork URLs only — no live Google scraping")
    parser.add_argument("--no-google", action="store_true",
                        help="Skip Google dorking entirely")
    parser.add_argument("--no-github", action="store_true",
                        help="Skip GitHub search entirely")
    parser.add_argument("--delay", type=float, default=3.0, metavar="N",
                        help="Seconds between requests (default: 3)")
    parser.add_argument("--max-results", type=int, default=10, metavar="N",
                        help="Max results per query (default: 10)")
    parser.add_argument("--output", metavar="FILE",
                        help="Save results to JSON file")
    args = parser.parse_args()

    # Validate / normalise inputs
    target = args.target.lower().strip().lstrip("https://").lstrip("http://").rstrip("/")
    need_github = not args.no_github and (
        args.github_token or args.github_org or args.github_user or args.github_search
    )
    if need_github and not args.github_token:
        console.print("[red]--github-token required for GitHub search[/]")
        sys.exit(1)

    search_terms: list[str] = []
    if args.github_search:
        search_terms = [t.strip() for t in args.github_search.split(",") if t.strip()]

    categories = ALL_CATEGORIES
    if args.categories:
        categories = [c.strip() for c in args.categories.split(",") if c.strip()]
        bad = [c for c in categories if c not in DORK_CATEGORIES]
        if bad:
            console.print(f"[red]Unknown categories: {', '.join(bad)}[/]")
            console.print(f"Available: {', '.join(ALL_CATEGORIES)}")
            sys.exit(1)

    print_header(target, args.github_org or "", args.github_user or "", search_terms)

    console.print(Rule(" Scanning ", style="dim"))
    console.print()

    google_results: list[Result] = []
    github_results: list[GithubResult] = []

    if not args.no_google:
        google_results = run_google_dorks(
            target=target,
            categories=categories,
            max_results=args.max_results,
            delay=args.delay,
            dorks_only=args.dorks_only,
        )

    if need_github:
        github_results = run_github_search(
            target=target,
            token=args.github_token,
            org=args.github_org or "",
            user=args.github_user or "",
            search_terms=search_terms,
            max_results=args.max_results,
            delay=args.delay,
        )
    elif not args.no_github and not args.github_token:
        console.print("  [dim]→ GitHub: skipped (no --github-token provided)[/]\n")

    print_google_results(google_results, args.dorks_only)

    if github_results:
        print_github_results(github_results)

    print_summary(google_results, github_results)

    if args.output:
        export_json(target, google_results, github_results, args.output)


if __name__ == "__main__":
    main()
