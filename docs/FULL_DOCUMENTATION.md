# Enterprise Honeypot + SIEM System — Complete Documentation

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture](#2-architecture)
3. [Transparent Authentication Proxy](#3-transparent-authentication-proxy)
4. [Attack Signature Engine](#4-attack-signature-engine)
5. [SIEM Engine](#5-siem-engine)
6. [SIEM Dashboard](#6-siem-dashboard)
7. [Deception Layer](#7-deception-layer)
8. [Alert System](#8-alert-system)
9. [Quick Start](#9-quick-start)
10. [API Reference](#10-api-reference)
11. [Operations Runbook](#11-operations-runbook)
12. [Deployment](#12-deployment)
13. [Security Considerations](#13-security-considerations)

---

## 1. System Overview

This system implements a **transparent authentication proxy** combined with a **full SIEM (Security Information and Event Management)** platform, deployed in front of a banking web application.

### Core concept

Every visitor to the banking login page passes through the transparent proxy. The proxy runs all 200+ attack signatures against the request in real time, accumulates a per-session risk score, and silently routes the request to one of three destinations:

| Routing Decision | Condition | What Happens |
|---|---|---|
| **ALLOW** | No attack signatures triggered, risk score low | Credentials verified against real bank user database. Legitimate customers log in normally. |
| **DECEIVE** | Attack signatures fired OR risk score crosses SIEM_DECEIVE_THRESHOLD (default 45) | Request silently routed to honeypot. Attacker receives convincing fake responses and wastes time exploring fake endpoints. |
| **BLOCK** | Risk score crosses SIEM_BLOCK_THRESHOLD (default 120) OR attacker explicitly blocked by analyst | Hard 429 response. Session pinned to BLOCK for 24 hours. |

The attacker receives a completely normal-looking response in all cases. They never know they have been routed away from the real application.

### What is monitored

Every request — legitimate or malicious — produces a structured SIEM alert record. The SIEM dashboard provides:

- Real-time live feed of attack events
- Alert queue with analyst triage workflow
- KPI cards: critical unacknowledged alerts, deceived sessions, blocked sessions, brute-force attempts
- Hourly and 30-day trend charts
- Attack-type breakdown bar charts
- Severity distribution pie chart
- Routing decision funnel (sankey-style)
- Geographic intelligence heat map
- Hour-of-day × day-of-week attack intensity heatmap
- Captured credentials with strength analysis
- IOC extraction feed
- Per-session risk score timeline (drilldown)
- Configurable alert rules with Slack and email channels

---

## 2. Architecture

```
Internet
  │
  ▼
Nginx (port 80 / 443)
  │
  ├─► /                   React honeypot frontend  ← what attackers see
  ├─► /real-site/         Static marketing site
  ├─► /api/auth/login/    Transparent Auth Proxy  ← SIEM engine here
  ├─► /api/               Deception endpoints
  ├─► /monitor/siem/      SIEM Dashboard HTML
  ├─► /monitor/           Classic monitor dashboard
  └─► /django-admin/      Django admin
```

### Service stack

| Service | Purpose |
|---|---|
| Django 4.2 (Gunicorn) | API + transparent proxy + SIEM API + monitor dashboard |
| Celery Worker | Async threat intel enrichment, alert dispatch |
| Celery Beat | Scheduled jobs: log pruning, daily SIEM reports |
| PostgreSQL 16 | Persistent storage for all SIEM data |
| Redis 7 | Session risk scores, rate limits, burst detection, task queue |
| Nginx 1.25 | Reverse proxy, TLS termination, scanner UA blocking |
| Prometheus | Metrics scraping |
| Grafana | Metrics dashboards |

### Database models

| Model | Purpose |
|---|---|
| `MonitorUser` | Operator accounts with RBAC (admin / analyst / viewer) |
| `RealBankUser` | Legitimate banking customers (bcrypt-hashed passwords) |
| `AttackerSession` | One record per unique attacker fingerprint, cumulative threat scoring |
| `AttackEvent` | One record per HTTP request captured by the honeypot |
| `CapturedCredential` | Every username/password pair submitted to login traps |
| `SiemAlert` | Structured alert produced by SIEM engine for every evaluated request |
| `LoginAttempt` | Audit record of every login POST with routing decision |
| `AlertRule` | Operator-configured threshold rules with notification channels |
| `DeceptionAsset` | Registry of configured honeytokens and fake endpoints |
| `MonitorAuditLog` | Immutable audit trail of all operator actions |

---

## 3. Transparent Authentication Proxy

**File:** `backend/core/views_proxy.py`

**Endpoint:** `POST /api/auth/login/`

This is the single most security-critical view. Every login attempt in the entire banking application passes through it.

### Processing sequence

```
POST /api/auth/login/
    │
    ▼
1. Extract: IP, User-Agent, Accept headers, body (username, password)
    │
    ▼
2. Build fingerprint (SHA-256 of IP + UA + Accept-Language + Accept-Encoding)
    │
    ▼
3. SIEM Engine evaluation:
   a. Run 200+ regex signatures against full request corpus
   b. Check credential analysis (default creds, common passwords)
   c. Check brute-force counter (Redis, 10-minute window)
   d. Check burst rate (Redis, 1-minute window)
   e. Add score delta to session cumulative score (Redis)
   f. Determine routing decision: ALLOW / DECEIVE / BLOCK
    │
    ▼
4. Fire alert escalation (async, best-effort):
   - Create SiemAlert record
   - Notify Slack / email if severity = high or critical
    │
    ├─► BLOCK  → Return HTTP 429 "Too many requests"
    │
    ├─► DECEIVE → Return convincing fake response:
    │              - SQL error with query fragment (for SQLi attempts)
    │              - Fake JWT + user object (for default creds)
    │              - Normal "invalid credentials" (for other attempts)
    │
    └─► ALLOW  → Verify against RealBankUser table (bcrypt):
                  - Match → Issue real JWT, update last_login
                  - No match → Increment fail counter, return 401
                               (if fail count ≥ SIEM_BRUTE_LIMIT → flip to DECEIVE)
```

### Constant-time protection

All credential lookups perform a dummy `bcrypt.checkpw()` even when the username is not found, preventing timing-based username enumeration.

---

## 4. Attack Signature Engine

**File:** `backend/core/siem/signatures.py`

Contains **214 regex signatures** across **18 attack categories**:

| # | Category | Signatures | Example Rules |
|---|---|---|---|
| 1 | SQL Injection | 30 | `sqli_union_select`, `sqli_xp_cmdshell`, `sqli_time_sleep`, `sqli_outfile` |
| 2 | XSS | 24 | `xss_script_open`, `xss_event_handler`, `xss_svg_event`, `xss_data_uri_html` |
| 3 | Path Traversal | 16 | `traversal_etc_passwd`, `traversal_null_byte`, `traversal_proc_self` |
| 4 | Command Injection | 21 | `cmdinj_unix_enum`, `cmdinj_netcat`, `cmdinj_powershell`, `cmdinj_iex` |
| 5 | SSRF | 15 | `ssrf_aws_imds`, `ssrf_gcp_metadata`, `ssrf_file_scheme`, `ssrf_gopher_scheme` |
| 6 | XXE | 6 | `xxe_entity_system`, `xxe_doctype_system`, `xxe_param_entity` |
| 7 | Deserialization | 7 | `deser_java_base64`, `deser_php_object`, `deser_python_pickle` |
| 8 | LFI / RFI | 8 | `lfi_php_filter`, `lfi_phar_wrapper`, `rfi_remote_include` |
| 9 | SSTI | 9 | `ssti_double_brace`, `ssti_flask_config`, `ssti_python_mro` |
| 10 | LDAP Injection | 6 | `ldap_wildcard_or`, `ldap_cn_wildcard`, `ldap_and_filter` |
| 11 | NoSQL Injection | 6 | `nosql_where`, `nosql_comparison_op`, `nosql_js_return_true` |
| 12 | HTTP Header Injection | 3 | `header_crlf_inject`, `header_crlf_encoded`, `header_response_split` |
| 13 | Open Redirect | 3 | `redirect_open`, `redirect_protocol_rel`, `redirect_unc_path` |
| 14 | Auth Abuse | 7 | `auth_default_creds`, `auth_xff_spoof`, `auth_empty_password` |
| 15 | Brute Force | 3 | `bruteforce_tool_ua`, `bruteforce_common_pass`, `bruteforce_pattern_pass` |
| 16 | Reconnaissance | 14 | `recon_git_config`, `recon_spring`, `recon_attack_tool_ua`, `recon_backup_file` |
| 17 | Web Shell | 5 | `webshell_php_exec`, `webshell_php_b64`, `webshell_aspx_cmd` |
| 18 | Prototype Pollution | 3 | `proto_pollution`, `proto_constructor`, `proto_quoted` |

Each signature is a 3-tuple `(regex, rule_id, confidence)`. The engine:
1. Lowercases the full request corpus (path + query + body + headers + credentials).
2. Tests every signature.
3. Groups hits by category and takes the maximum confidence per category.
4. Returns the category with the highest confidence as the primary `attack_type`.

---

## 5. SIEM Engine

**File:** `backend/core/siem/engine.py`

### Session risk scoring

Risk scores are stored in Redis under `siem:score:<fingerprint>` with a 1-hour TTL (refreshed on each hit).

| Attack Type | Score Delta |
|---|---|
| Web Shell | 80 |
| Command Injection | 70 |
| SSRF / XXE / Deserialization | 65 |
| Path Traversal | 55 |
| SSTI / RFI | 55 |
| SQL Injection | 50 |
| LFI / LDAP / NoSQL | 50 |
| Auth Bypass | 40 |
| XSS / Header Injection | 35 |
| Open Redirect | 30 |
| Prototype Pollution | 30 |
| Brute Force | 20 |
| Reconnaissance | 15 |
| Other | 5 |

Delta is multiplied by the signature confidence before being added:
`delta = base_weight × confidence`

### Routing thresholds (configurable via env vars)

| Variable | Default | Effect |
|---|---|---|
| `SIEM_DECEIVE_THRESHOLD` | 45 | Score at which session is silently diverted to honeypot |
| `SIEM_BLOCK_THRESHOLD` | 120 | Score at which session is hard-blocked (HTTP 429) |
| `SIEM_BURST_LIMIT` | 20 | Requests per minute before burst detection triggers DECEIVE |
| `SIEM_BRUTE_LIMIT` | 8 | Failed logins per 10 minutes before brute-force flag and DECEIVE |

### Immediate deception (single-hit override)

A single high-confidence critical attack bypasses the threshold accumulation and immediately pins the session to DECEIVE:

```
confidence >= 0.85 AND attack_type in {
  web_shell, command_injection, ssrf, xxe, deserialization,
  sql_injection, ssti, lfi, rfi
}
→ DECEIVE immediately, regardless of accumulated score
```

---

## 6. SIEM Dashboard

**URL:** `http://localhost/monitor/siem/`

Single-page application (no framework dependency — vanilla JS + Chart.js 4). All data is loaded via the SIEM JSON API with JWT authentication in the `Authorization` header.

### Dashboard sections

| Section | Charts / Widgets |
|---|---|
| **SIEM Dashboard** | 8 KPI cards, hourly stacked bar chart (24 h), severity doughnut, routing doughnut, 30-day line trend, attack-type horizontal bar, live feed (auto-refresh 10 s), unacknowledged alert queue |
| **Attack Analytics** | Attack type bar chart, confidence distribution bar chart, detailed table with avg confidence and unique sources |
| **Attack Heatmap** | 7×24 intensity matrix (day-of-week × hour-of-day), colour gradient from blue (low) to red (high) |
| **Login Funnel** | Funnel bar chart (total → real app → honeypot → blocked → success/failure), hourly stacked bar, top attacker usernames table, top attacker IPs table |
| **Geo Intelligence** | Country bar chart, country doughnut, country detail table with avg threat score |
| **Alert Queue** | Filterable table (severity, routing), per-row Ack button, bulk Ack |
| **Attacker Sessions** | Table with threat score bar, threat level badge, blocked status |
| **Captured Credentials** | Table with password strength badge, default-credential flag |
| **IOC Feed** | Table of extracted IPs / domains / hashes, IOC type doughnut |
| **Alert Rules** | Table of configured SIEM alert rules |
| **Real Bank Users** | Table of legitimate customers registered in the proxy |
| **Audit Log** | Operator action history |

### Auto-refresh intervals

| Data | Refresh interval |
|---|---|
| Live event feed | 10 seconds |
| Overview KPIs + charts | 30 seconds |
| Other pages | Manual (Refresh button) |

---

## 7. Deception Layer

When the SIEM engine decides DECEIVE, the request continues to one of the deception views in `backend/core/views_deception.py`. The attacker receives fabricated responses designed to:

- **Encourage further probing** — fake SQL errors, fake JWT tokens, fake admin panels, fake API key lists, fake database consoles, fake backup listings.
- **Waste time** — artificial response delays (100 ms to 3 s) proportional to threat score.
- **Collect intelligence** — every endpoint logs the full request body, captures credentials, extracts IOCs.

### Deception endpoints available

| Path | Trap Type | Fake Response |
|---|---|---|
| `/api/auth/login/` | Login trap | SQL error fragment, fake JWT for default creds |
| `/api/auth/verify/` | MFA trap | Fake MFA verification |
| `/api/admin/dashboard/` | Admin panel | Fake dashboard with system stats |
| `/api/admin/users/` | User list | Fake user table with debug SQL |
| `/api/admin/settings/` | Config dump | Fake secrets: DB password, Redis password, AWS keys, JWT secret |
| `/api/admin/database/` | DB console | Echoes query, returns fake result set |
| `/api/admin/api-keys/` | API keys | Generates fake live API keys |
| `/api/admin/backup/` | Backup list | Lists fake .sql.gz files with download URLs |
| `/api/admin/files/` | File browser | Lists .env, database_backup.sql.gz, users_export.csv |
| `/api/admin/download/` | File download | Returns fake .env content with fabricated credentials |
| `/api/internal/config/` | Config dump | Full fake internal config including AWS, Redis, internal service URLs |
| `/api/search/` | Search | Reflects query back (simulates XSS / SQLi reflection) |
| `/.env`, `/.git/config` | Scanner traps | Routes to deception views |
| `/wp-admin/`, `/phpmyadmin/` | CMS/DB traps | Routes to fake admin panel |

All "sensitive" values returned (passwords, API keys, JWT secrets, AWS keys) are completely fabricated. None are real.

---

## 8. Alert System

**File:** `backend/core/siem/alerts.py`

### Alert lifecycle

```
Request arrives
  → SIEM engine evaluates
  → SiemAlert record created (always)
  → If severity = high or critical AND not duplicate within cooldown:
      → Slack webhook (if configured)
      → Email via SMTP (if configured)
  → Operator sees alert in SIEM dashboard queue
  → Analyst acknowledges with optional note
```

### Deduplication

Alerts for the same fingerprint + severity are deduplicated within a 5-minute cooldown window (configurable per rule) to prevent notification flood during a sustained attack.

### Default alert rules (seeded via `make seed-rules`)

| Rule | Condition | Channel | Auto-Block |
|---|---|---|---|
| Critical Severity | severity=critical, confidence≥80% | Slack + Email | Yes |
| Web Shell Detection | type=web_shell, confidence≥70% | Slack + Email | Yes |
| Command Injection | type=command_injection, confidence≥75% | Slack + Email | Yes |
| SQL Injection High | type=sql_injection, confidence≥85% | Slack | No |
| SSRF Attempt | type=ssrf, confidence≥80% | Slack + Email | Yes |
| Brute Force Escalation | type=brute_force, score≥60 | Slack | No |
| Deserialization | type=deserialization, confidence≥70% | Slack + Email | Yes |
| High Score Warning | any type, score≥80 | Slack | No |

---

## 9. Quick Start

### Prerequisites

- Docker 24.0+
- Docker Compose 2.20+
- Make

### Minimum setup (3 commands)

```bash
# 1. Copy and configure secrets
cp .env.example .env
# Edit .env – change SECRET_KEY, POSTGRES_PASSWORD, MONITOR_JWT_SECRET, REAL_BANK_JWT_SECRET

# 2. Build and start
make build && make up

# 3. Initialise (migrate, create admin, seed demo data, seed alert rules)
make setup
```

### Access points after setup

| URL | Description |
|---|---|
| `http://localhost` | Banking application (honeypot frontend — what attackers see) |
| `http://localhost/monitor/siem/` | SIEM Intelligence Center (operator) |
| `http://localhost/monitor/login/` | Monitor login page |
| `http://localhost/monitor/` | Classic monitor dashboard |
| `http://localhost:3001` | Grafana (admin / value from GRAFANA_PASSWORD) |
| `http://localhost:9090` | Prometheus |

### Demo credentials

After `make setup`:

SIEM dashboard login:
- Username: `cyber_admin`
- Password: `CyB3r_P@ssw0rd!99`

Demo legitimate bank users (created by `make seed-users`):
- `michael.scott` / `Michael$c0tt!123`
- `dwight.schrute` / `B3etsBearsB$G`
- `jim.halpert` / `Pam!1234567`

Test attack simulation:
```bash
# SQL injection — should be DECEIVED
curl -s -X POST http://localhost/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR 1=1--","password":"x"}' | python3 -m json.tool

# Legitimate login — should be ALLOWED and verify against real DB
curl -s -X POST http://localhost/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username":"michael.scott","password":"Michael$c0tt!123"}' | python3 -m json.tool

# Default credentials — should be DECEIVED with fake token
curl -s -X POST http://localhost/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | python3 -m json.tool

# Command injection — should be DECEIVED immediately
curl -s -X POST http://localhost/api/search/ \
  -H "Content-Type: application/json" \
  -d '{"q":"test; cat /etc/passwd"}' | python3 -m json.tool

# Check SIEM dashboard — alerts should appear
open http://localhost/monitor/siem/
```

---

## 10. API Reference

All SIEM API endpoints require `Authorization: Bearer <token>`.
Obtain a token from `POST /monitor/auth/login/`.

### Authentication

```
POST /monitor/auth/login/
Body: { "username": "admin", "password": "AdminPass1!" }
Response: { "access_token": "...", "refresh_token": "...", "expires_in": 14400, "role": "admin" }

POST /monitor/auth/refresh/
Body: { "refresh_token": "..." }

POST /monitor/auth/logout/
```

### SIEM endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/monitor/api/siem/overview/` | GET | Full SIEM overview: KPIs, all chart data, alert queue |
| `/monitor/api/siem/live/?seconds=15` | GET | Events from last N seconds |
| `/monitor/api/siem/alerts/` | GET | Paginated alert queue with filters |
| `/monitor/api/siem/alerts/{id}/ack/` | POST | Acknowledge one alert |
| `/monitor/api/siem/alerts/bulk-ack/` | POST | Acknowledge multiple alerts |
| `/monitor/api/siem/funnel/?hours=24` | GET | Login funnel analytics |
| `/monitor/api/siem/heatmap/?days=30` | GET | Hour × day attack intensity matrix |
| `/monitor/api/siem/rules/` | GET / POST | List or create alert rules |
| `/monitor/api/siem/rules/{id}/` | PUT / DELETE | Update or deactivate a rule |
| `/monitor/api/siem/timeline/{fingerprint}/` | GET | Per-session score accumulation timeline |
| `/monitor/api/siem/iocs/?hours=48` | GET | Aggregated IOC feed |
| `/monitor/api/siem/real-users/` | GET / POST | Manage legitimate bank users |

### SIEM overview response shape

```json
{
  "kpis": {
    "total_alerts": 1423,
    "alerts_1h": 47,
    "alerts_24h": 312,
    "critical_unacked": 3,
    "high_unacked": 12,
    "sessions_deceived": 89,
    "sessions_blocked": 14,
    "real_logins_24h": 23,
    "brute_force_24h": 47,
    "unique_attackers_24h": 61,
    "avg_confidence": 0.78,
    "top_attack_type": "sql_injection"
  },
  "severity_dist": [{"severity": "high", "count": 140}, ...],
  "hourly_trend": [{"hour": "2024-01-15T14:00:00Z", "total": 23, "critical": 4, "high": 8, "medium": 11}, ...],
  "daily_trend": [{"date": "2024-01-14", "count": 287}, ...],
  "attack_breakdown": [{"attack_type": "sql_injection", "count": 89, "avg_conf": 0.87, "unique_fps": 34}, ...],
  "routing_funnel": {"total_logins": 210, "routed_real": 23, "routed_deceive": 164, "blocked": 23, ...},
  "unacked_alerts": [{...}, ...],
  "geo_distribution": [{"country_code": "CN", "country_name": "China", "sessions": 47, "avg_score": 83}, ...]
}
```

---

## 11. Operations Runbook

### Common management commands

```bash
# Create operator account
make create-user USER=analyst1 PASS=SecurePass ROLE=analyst

# Create legitimate bank users
make seed-users

# Seed default alert rules
make seed-rules

# Manually block an attacker fingerprint (via Django shell)
docker compose exec backend python manage.py shell
>>> from core.siem.engine import siem
>>> siem.force_block('fingerprint_hash_here')

# View all blocked sessions
docker compose exec backend python manage.py shell
>>> from core.models import AttackerSession
>>> AttackerSession.objects.filter(is_blocked=True).values('ip_address','block_reason')

# Add a legitimate user via API
curl -X POST http://localhost/monitor/api/siem/real-users/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"newuser","password":"StrongPass!123","email":"user@bank.com","full_name":"New User","account_number":"4001-9999-0001"}'
```

### Tuning the SIEM thresholds

| Scenario | Recommendation |
|---|---|
| Too many false positives (legitimate users being deceived) | Increase `SIEM_DECEIVE_THRESHOLD` (e.g. 60) |
| Attackers not being caught fast enough | Decrease `SIEM_DECEIVE_THRESHOLD` (e.g. 30) |
| Brute force not detected quickly enough | Decrease `SIEM_BRUTE_LIMIT` (e.g. 5) |
| High traffic site triggering burst detection | Increase `SIEM_BURST_LIMIT` (e.g. 50) |

All thresholds are environment variables — change in `.env` and `make restart`.

### Monitoring SIEM health

```bash
# Check alert rate
docker compose exec postgres psql -U honeypot -d honeypot \
  -c "SELECT severity, count(*) FROM siem_alerts WHERE timestamp > NOW()-INTERVAL '1 hour' GROUP BY severity;"

# Check routing decisions
docker compose exec postgres psql -U honeypot -d honeypot \
  -c "SELECT outcome, count(*) FROM login_attempts WHERE timestamp > NOW()-INTERVAL '24 hours' GROUP BY outcome;"

# Check Redis session scores
docker compose exec redis redis-cli -a $REDIS_PASSWORD keys 'siem:score:*' | wc -l
```

---

## 12. Deployment

### Docker Compose (recommended for a single server)

```bash
cp .env.example .env        # configure all secrets
make build && make up
make setup
./scripts/deployment/setup-ssl.sh yourdomain.com admin@yourdomain.com
```

### Railway (backend) + Vercel (frontend)

**Backend (Railway):**
1. Connect GitHub repository, root directory = `backend/`.
2. Add PostgreSQL and Redis plugins.
3. Set env vars: `SECRET_KEY`, `POSTGRES_PASSWORD`, `MONITOR_JWT_SECRET`, `REAL_BANK_JWT_SECRET`, `DEBUG=False`.
4. Run: `python manage.py migrate && python manage.py seed_real_users && python manage.py seed_alert_rules`.
5. Create admin: `python manage.py create_monitor_user cyber_admin CyB3r_P@ssw0rd!99 --role admin`.

**Frontend (Vercel):**
1. `cd frontend && echo "VITE_API_URL=https://your-app.up.railway.app/api" > .env.production`
2. `vercel --prod`
3. Add Vercel domain to `CORS_ALLOWED_ORIGINS` in Railway.

### Kubernetes (production)

```bash
kubectl create namespace honeypot-production
kubectl create secret generic honeypot-secrets \
  --from-literal=SECRET_KEY="..." \
  --from-literal=POSTGRES_PASSWORD="..." \
  --from-literal=MONITOR_JWT_SECRET="..." \
  --from-literal=REAL_BANK_JWT_SECRET="..." \
  -n honeypot-production

make deploy-prod
```

---

## 13. Security Considerations

### What is protected

- All operator endpoints (`/monitor/`) require a JWT issued by `MONITOR_JWT_SECRET`. Without the token the SIEM dashboard is inaccessible.
- All legitimate customer logins verify bcrypt hashes against `RealBankUser`. Passwords are never stored in plaintext.
- All "sensitive" data returned by deception endpoints is completely fabricated. No real credentials, keys, or configuration are ever exposed.
- The SIEM engine performs all classification server-side. The attacker's browser receives no indication that their request was classified.

### Network hardening for production

In `nginx.conf`, uncomment and configure the IP allowlist for `/monitor/`:
```nginx
location /monitor/ {
    allow 10.0.0.0/8;       # internal network
    allow 203.0.113.50/32;  # your IP
    deny  all;
    ...
}
```

### Secret management

The three JWT secrets must be distinct and sufficiently random:
- `SECRET_KEY` — Django signing key
- `MONITOR_JWT_SECRET` — operator dashboard tokens
- `REAL_BANK_JWT_SECRET` — customer session tokens

Generate each with:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

### Legal notice

Honeypot systems must be deployed only on infrastructure you own and control, with appropriate authorisation. Ensure compliance with all applicable laws and regulations in your jurisdiction before deployment. The authors of this system accept no liability for misuse.
