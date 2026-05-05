# Architecture Overview

## System Components

```
Internet
    |
    v
[Nginx Reverse Proxy]  (port 80 / 443)
    |
    +---> /                  React honeypot frontend  (attacker view)
    +---> /real-site/        Static marketing site
    +---> /api/              Django deception endpoints  (the traps)
    +---> /monitor/          Protected monitoring dashboard (operator only)
    +---> /django-admin/     Django admin
```

### Backend services

| Service | Image | Purpose |
|---|---|---|
| backend | custom Django 4.2 | API + monitoring dashboard |
| celery-worker | same image | Async enrichment tasks |
| celery-beat | same image | Scheduled jobs (log pruning, reports) |
| postgres | postgres:16-alpine | Primary data store |
| redis | redis:7-alpine | Cache, task queue, channel layers |
| nginx | nginx:1.25-alpine | TLS termination, routing |
| prometheus | prom/prometheus | Metrics scraping |
| grafana | grafana/grafana | Metrics dashboards |

## Data Flow

```
Attacker request
  --> Nginx
    --> Django (port 8000)
      --> AttackDetectionMiddleware
          1. Fingerprint session (IP + UA + headers)
          2. Get-or-create AttackerSession
          3. Rate-limit check (Redis)
          4. Block check
          5. Call view (deception endpoint)
          6. Run ThreatAnalyzer on request corpus
          7. Persist AttackEvent
          8. Update AttackerSession.threat_score
          9. Auto-block if threshold exceeded
```

## Database Models

```
MonitorUser          (operator accounts, RBAC)
AttackerSession      (one per unique fingerprint, cumulative scoring)
AttackEvent          (one per HTTP request, full payload capture)
CapturedCredential   (username/password pairs from login traps)
DeceptionAsset       (configured honeytoken/endpoint registry)
DeceptionInteraction (record of asset access)
MonitorAuditLog      (immutable operator action trail)
```

## Threat Scoring

Each AttackEvent adds a weighted delta to the parent AttackerSession:

| Attack type | Score delta |
|---|---|
| command_injection | 40 |
| path_traversal / ssrf / xxe | 35 |
| sql_injection | 30 |
| data_exfil | 30 |
| xss | 25 |
| auth_bypass | 20 |
| brute_force | 15 |
| reconnaissance | 10 |
| api_probe | 5 |
| login_attempt | 5 |

Threat levels: minimal (0–9) / low (10–39) / medium (40–69) / high (70–99) / critical (100+).
Sessions are auto-blocked when score reaches the configured AUTO_BLOCK_THRESHOLD (default 100).

## Security Boundaries

- All operator endpoints (`/monitor/`, `/django-admin/`) require JWT authentication.
- Honeypot endpoints (`/api/`) are intentionally open and log everything.
- Nginx can whitelist IP ranges for `/monitor/` in production (see `nginx.conf`).
- MONITOR_JWT_SECRET must differ from Django SECRET_KEY.
- All fabricated "sensitive" data returned by deception endpoints is fake.
