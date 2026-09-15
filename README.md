# dorksearch

Google dorking + GitHub code search for OSINT and pentest recon. Runs ~54 Google dorks across 9 categories and up to 39 GitHub code search queries against a target domain, organisation, or user. Results are severity-triaged and optionally exported to JSON.

---

## Installation

```bash
# Required
pip install requests rich

# Optional — enables live Google scraping (URL-only mode without it)
pip install googlesearch-python
```

---

## Usage

```
python3 dorksearch.py <target> [options]
```

| Flag | Description |
|------|-------------|
| `--github-token TOKEN` | GitHub personal access token (required for GitHub search) |
| `--github-org ORG` | Scope GitHub search to this organisation |
| `--github-user USER` | Scope GitHub search to this user |
| `--github-search TERM[,TERM]` | Search term(s) for domain-referenced GitHub queries. Replaces the raw target domain — see note below |
| `--categories LIST` | Comma-separated dork categories to run (default: all) |
| `--dorks-only` | Print clickable Google URLs only, no live scraping |
| `--no-google` | Skip Google dorking |
| `--no-github` | Skip GitHub search |
| `--delay N` | Seconds between requests (default: 3) |
| `--max-results N` | Max results per query (default: 10) |
| `--output FILE` | Save results to JSON |

### Examples

```bash
# Google dorks only, URL mode (no googlesearch-python needed)
python3 dorksearch.py example.com --dorks-only

# Run specific categories with live Google scraping
python3 dorksearch.py example.com --categories admin,files,errors

# GitHub org scan
python3 dorksearch.py example.com --github-token ghp_xxx --github-org acme-corp

# Domain-referenced GitHub search (email format is much tighter than bare domain)
python3 dorksearch.py example.com --github-token ghp_xxx --github-search "@example.com"

# Multiple search terms + org scope + export
python3 dorksearch.py example.com \
  --github-token ghp_xxx \
  --github-search "@example.com,acme-internal" \
  --github-org acme-corp \
  --no-google \
  --output results.json
```

### `--github-search` note

Firing the raw target domain (`"example.com"`) against all of GitHub returns thousands of unrelated results — documentation, random blog posts, unrelated projects. Pass a more specific string instead:

| Term | What it finds |
|------|---------------|
| `@example.com` | SMTP configs, hardcoded email creds, auth scripts |
| `acme-internal` | Internal hostnames or project codenames in config files |
| `vpn.example.com` | VPN hostnames baked into scripts or configs |
| `acme.corp` | Internal AD domain in PowerShell, connection strings |
| `@example.com,acme-internal` | Runs the full query set for each term independently |

Without `--github-search`, domain-referenced queries are skipped unless `--github-org` or `--github-user` is also set.

---

## Google Dork Categories

Run all categories by default or select with `--categories admin,files,errors`.

### `admin` — Admin & Remote Access Panels

| Severity | Description | Dork |
|----------|-------------|------|
| HIGH | phpMyAdmin | `site:{target} inurl:phpmyadmin` |
| MEDIUM | Admin panel | `site:{target} inurl:admin` |
| MEDIUM | WordPress admin | `site:{target} inurl:wp-admin` |
| MEDIUM | cPanel | `site:{target} inurl:cpanel` |
| MEDIUM | Remote access | `site:{target} inurl:remote` |
| MEDIUM | VPN portal | `site:{target} inurl:vpn` |
| MEDIUM | Citrix portal | `site:{target} inurl:citrix OR inurl:"Citrix"` |
| LOW | Login page | `site:{target} inurl:login` |
| LOW | Webmail | `site:{target} inurl:webmail` |

### `files` — Sensitive File Types

| Severity | Description | Dork |
|----------|-------------|------|
| CRITICAL | .env files | `site:{target} ext:env` |
| CRITICAL | SQL dumps | `site:{target} ext:sql` |
| CRITICAL | Private key files | `site:{target} ext:pem OR ext:key` |
| HIGH | Log files | `site:{target} ext:log` |
| HIGH | Backup files | `site:{target} ext:bak OR ext:backup` |
| HIGH | Config files | `site:{target} ext:conf OR ext:config` |
| HIGH | YAML/YML configs | `site:{target} ext:yaml OR ext:yml` |
| MEDIUM | INI files | `site:{target} ext:ini` |
| MEDIUM | XML configs | `site:{target} ext:xml inurl:config` |
| MEDIUM | PHP source/info | `site:{target} ext:php intitle:phpinfo` |
| LOW | Shell scripts | `site:{target} ext:sh` |

### `listings` — Directory Listings

| Severity | Description | Dork |
|----------|-------------|------|
| HIGH | Directory listing | `site:{target} intitle:"index of"` |
| HIGH | FTP listing | `site:{target} intitle:"index of /" inurl:ftp` |
| MEDIUM | Open directory | `site:{target} intitle:"directory listing"` |

### `docs` — Exposed Documents

| Severity | Description | Dork |
|----------|-------------|------|
| HIGH | Confidential PDFs | `site:{target} "confidential" ext:pdf` |
| HIGH | Internal docs | `site:{target} "internal use only"` |
| MEDIUM | Spreadsheets | `site:{target} ext:xlsx OR ext:xls OR ext:csv` |
| MEDIUM | Network diagrams | `site:{target} ext:vsd OR ext:vsdx` |
| LOW | PDFs | `site:{target} ext:pdf` |
| LOW | Word documents | `site:{target} ext:docx OR ext:doc` |
| LOW | Presentations | `site:{target} ext:pptx OR ext:ppt` |

### `errors` — Error Messages & Stack Traces

| Severity | Description | Dork |
|----------|-------------|------|
| HIGH | MySQL errors | `site:{target} "Warning: mysql_fetch"` |
| HIGH | MySQL errors (alt) | `site:{target} "MySQL Error"` |
| HIGH | Oracle errors | `site:{target} "ORA-" error` |
| HIGH | JDBC exceptions | `site:{target} "java.sql.SQLException"` |
| MEDIUM | PHP warnings | `site:{target} "PHP Warning"` |
| MEDIUM | Stack traces | `site:{target} "stack trace"` |
| MEDIUM | ASP.NET errors | `site:{target} "Server Error in" "Application"` |
| MEDIUM | Python tracebacks | `site:{target} "Traceback (most recent call"` |

### `cloud` — Cloud Storage

| Severity | Description | Dork |
|----------|-------------|------|
| HIGH | S3 buckets | `site:s3.amazonaws.com "{target}"` |
| HIGH | Google Cloud Storage | `site:storage.googleapis.com "{target}"` |
| HIGH | Azure Blob | `site:blob.core.windows.net "{target}"` |
| MEDIUM | DigitalOcean Spaces | `site:digitaloceanspaces.com "{target}"` |

### `repos` — Code Repositories & Paste Sites

| Severity | Description | Dork |
|----------|-------------|------|
| HIGH | Pastebin leaks | `site:pastebin.com "{target}"` |
| MEDIUM | GitHub references | `site:github.com "{target}"` |
| MEDIUM | GitLab references | `site:gitlab.com "{target}"` |
| MEDIUM | Gists | `site:gist.github.com "{target}"` |
| MEDIUM | Trello boards | `site:trello.com "{target}"` |
| MEDIUM | Postman collections | `site:postman.com "{target}"` |

### `creds` — Credential Exposure

| Severity | Description | Dork |
|----------|-------------|------|
| HIGH | Passwords in pages | `site:{target} intext:password` |
| HIGH | API keys in pages | `site:{target} intext:"api key"` |
| HIGH | Tokens in pages | `site:{target} intext:"access token"` |
| HIGH | Credentials in URLs | `site:{target} inurl:password` |
| MEDIUM | Default creds page | `site:{target} "default password"` |

### `subdomains` — Subdomain Enumeration

| Severity | Description | Dork |
|----------|-------------|------|
| INFO | Subdomain enumeration | `site:*.{target}` |

---

## GitHub Search Queries

### Domain-referenced (requires `--github-search`)

Each query substitutes your `--github-search` term for `{term}`. Run against all of GitHub — finds your target mentioned in any public repository.

| Severity | Description | Query |
|----------|-------------|-------|
| CRITICAL | Private RSA keys | `"{term}" "BEGIN RSA PRIVATE KEY"` |
| CRITICAL | Private keys (PKCS8) | `"{term}" "BEGIN PRIVATE KEY"` |
| CRITICAL | Private EC keys | `"{term}" "BEGIN EC PRIVATE KEY"` |
| CRITICAL | AWS access keys | `"{term}" "AKIA"` |
| HIGH | Hardcoded passwords | `"{term}" password` |
| HIGH | API keys | `"{term}" api_key` |
| HIGH | API secrets | `"{term}" api_secret` |
| HIGH | Access tokens | `"{term}" access_token` |
| HIGH | Bearer tokens | `"{term}" "Bearer"` |
| HIGH | Database URLs | `"{term}" "DATABASE_URL"` |
| HIGH | JDBC connection strings | `"{term}" "jdbc:mysql" OR "jdbc:postgresql"` |
| HIGH | MongoDB connection strings | `"{term}" "mongodb://"` |
| HIGH | .env file references | `"{term}" filename:.env` |
| HIGH | Slack tokens | `"{term}" "xoxb-" OR "xoxp-"` |
| HIGH | SendGrid keys | `"{term}" "SG."` |
| HIGH | Stripe live keys | `"{term}" "sk_live_"` |
| HIGH | Twilio credentials | `"{term}" "TWILIO_ACCOUNT_SID"` |
| MEDIUM | Generic secrets | `"{term}" secret` |
| MEDIUM | Config files | `"{term}" filename:config.yml OR filename:config.json` |

### Org/user-scoped (requires `--github-org` or `--github-user`)

Scoped to a specific GitHub organisation or user. Replaces `{scope}` with the org/user name.

| Severity | Description | Query |
|----------|-------------|-------|
| CRITICAL | Private RSA keys | `"BEGIN RSA PRIVATE KEY" org:{scope}` |
| CRITICAL | Private keys (PKCS8) | `"BEGIN PRIVATE KEY" org:{scope}` |
| CRITICAL | Private EC keys | `"BEGIN EC PRIVATE KEY" org:{scope}` |
| CRITICAL | AWS access keys | `"AKIA" org:{scope}` |
| CRITICAL | Stripe live keys | `"sk_live_" org:{scope}` |
| CRITICAL | SSH private keys (RSA) | `filename:id_rsa org:{scope}` |
| CRITICAL | SSH private keys (ed25519) | `filename:id_ed25519 org:{scope}` |
| HIGH | Hardcoded passwords | `password org:{scope} filename:*.env OR filename:*.yml OR filename:*.json` |
| HIGH | API keys | `api_key org:{scope}` |
| HIGH | Database URLs | `"DATABASE_URL" org:{scope}` |
| HIGH | Secret keys | `"SECRET_KEY" org:{scope}` |
| HIGH | Private keys in configs | `"private_key" org:{scope}` |
| HIGH | Slack tokens | `"xoxb-" org:{scope}` |
| HIGH | .env files | `filename:.env org:{scope}` |
| HIGH | Password/credential files | `filename:passwords.txt OR filename:credentials.txt org:{scope}` |
| HIGH | JWT secrets | `"JWT_SECRET" OR "jwt_secret" org:{scope}` |
| HIGH | Connection strings | `"connection string" org:{scope}` |
| HIGH | AWS secret key | `"AWS_SECRET_ACCESS_KEY" org:{scope}` |
| HIGH | GCP service account | `filename:service_account.json org:{scope}` |
| LOW | Internal IPs in configs | `"192.168." OR "10.0." filename:*.env OR filename:*.yml org:{scope}` |

---

## Output

Results are printed to the terminal with severity colour-coding (CRITICAL → HIGH → MEDIUM → LOW → INFO) and a snippet of matching code for CRITICAL/HIGH GitHub findings.

Export to JSON with `--output results.json`:

```json
{
  "target": "example.com",
  "google": [
    {
      "severity": "CRITICAL",
      "category": "files",
      "description": ".env files",
      "url": "https://example.com/config/.env",
      "dork": "site:example.com ext:env"
    }
  ],
  "github": [
    {
      "severity": "HIGH",
      "description": "Hardcoded passwords",
      "repo": "acme-corp/deploy-scripts",
      "path": "config/prod.yml",
      "url": "https://github.com/acme-corp/deploy-scripts/blob/main/config/prod.yml",
      "snippet": "smtp_password: \"hunter2\""
    }
  ]
}
```

---

## GitHub token scopes

| Scope | What it enables |
|-------|----------------|
| *(none)* | Public repository search only |
| `repo` | Private repository search (repositories your account can access) |

Generate a token at **Settings → Developer settings → Personal access tokens**.
