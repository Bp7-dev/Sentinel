# Security Policy

## Security Model

Sentinel is designed with security as a core principle. It follows a **read-only, local-only** architecture that minimizes attack surface and eliminates common vulnerability classes.

### Core Security Principles

| Principle | Implementation |
|-----------|----------------|
| **Read-Only** | No system modifications, process control, or file writes |
| **Local-Only** | Binds exclusively to `127.0.0.1` — no network exposure |
| **No Dynamic Shell** | All subprocess commands are hardcoded strings |
| **No Authentication** | Local-only access eliminates credential theft vectors |
| **No Persistence** | All state resets on restart — no database, no logs |
| **Minimal Dependencies** | Only Flask, Werkzeug, and psutil required |
| **Path Privacy** | Executable paths are truncated to binary names before API responses |
| **Geo Lookup Optional** | HTTPS geolocation calls can be disabled via `SENTINEL_GEO_LOOKUP` environment variable |

### What Sentinel Does NOT Do

- ❌ Modify firewall rules
- ❌ Terminate processes
- ❌ Write to disk (except optional GeoIP cache in memory)
- ❌ Accept user input that reaches subprocess
- ❌ Connect to external services (except cached GeoIP lookups)
- ❌ Store credentials or secrets
- ❌ Run with elevated privileges

### Network Security

```
┌─────────────────────────────────────────────────────────┐
│                    YOUR MACHINE                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Sentinel (127.0.0.1:5000)          │   │
│  │                                                  │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐      │   │
│  │  │  psutil  │  │  socket  │  │subprocess│      │   │
│  │  │ (read)   │  │ (read)   │  │ (read)   │      │   │
│  │  └──────────┘  └──────────┘  └──────────┘      │   │
│  └─────────────────────────────────────────────────┘   │
│                         ▲                               │
│                         │ localhost only                │
│                         │                               │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Browser (localhost)                 │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
         ╳ No external network access
```

### Network & Privacy

- The only outbound network call is an **HTTPS** request to `ip-api.com` for geolocation, once per unique external IP. Disable entirely by setting `SENTINEL_GEO_LOOKUP=false` environment variable.
- No other external services are contacted; private/local IPs never leave the host.

### Subprocess Security

All subprocess calls use:
- **Hardcoded command arrays** — no string interpolation
- **No shell=True** — prevents shell injection
- **Timeout limits** — prevents hanging
- **Captured output only** — no interactive sessions

```python
# Example: UFW status check (hardcoded, no user input)
subprocess.run(
    ['sudo', '-n', 'ufw', 'status', 'verbose'],
    capture_output=True,
    text=True,
    timeout=5
)
```

### Information Disclosure Mitigations

- Process owner usernames are not returned by the API.
- Executable paths are truncated to the binary name before being sent to the frontend.

### Localhost Verification

- Default host binding is `127.0.0.1`. At startup Sentinel prints a warning if configured to bind to anything else (e.g., `0.0.0.0`).
- To verify, ensure `HOST` in `app.py` remains `127.0.0.1` or `localhost`.

### Running a Security Audit

From the repository root:

```bash
pip-audit -r requirements.txt
```

The audit runs pip-audit to check for vulnerable dependencies.

### GeoIP Privacy

- Local/private IP addresses are **never** sent to external services
- Public IP lookups use ip-api.com with aggressive caching (1-hour TTL)
- Optional offline mode with MaxMind GeoLite2 database
- Cache is in-memory only — cleared on restart

### Running the Security Audit

Sentinel includes a built-in security audit tool:

```bash
cd sentinel
python audit/audit.py
```

This performs:
- Static analysis with Bandit
- Dependency CVE scanning
- Hardcoded secrets detection
- Flask configuration validation
- Network binding verification

Reports are saved to `audit/AUDIT_YYYY-MM-DD.md`.

---

## Reporting a Vulnerability

If you discover a security vulnerability in Sentinel:

1. **Do NOT** open a public GitHub issue
2. Email the maintainer directly with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
3. Allow 48 hours for initial response
4. Coordinate disclosure timeline

### Scope

The following are considered security issues:
- Remote code execution
- Information disclosure
- Authentication bypass (if auth is ever added)
- Denial of service vulnerabilities

The following are NOT security issues:
- Issues requiring local access (Sentinel is local-only by design)
- Social engineering attacks
- Issues in dependencies (report to upstream)

---

## Security Checklist for Contributors

Before submitting a PR, verify:

- [ ] No hardcoded secrets, API keys, or passwords
- [ ] No `shell=True` in subprocess calls
- [ ] No user input reaches subprocess commands
- [ ] Flask debug mode is disabled
- [ ] App binds to `127.0.0.1` only
- [ ] No new external network dependencies
- [ ] Run `python audit/audit.py` and address any findings

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |

---

*Last updated: 2026-02-25*
