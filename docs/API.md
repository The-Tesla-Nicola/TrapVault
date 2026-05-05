# Monitor API Reference

All endpoints under `/monitor/api/` require a valid Bearer token obtained
from the login endpoint.  Requests without a valid token receive HTTP 401.

## Authentication

### POST /monitor/auth/login/

Request:
```json
{ "username": "admin", "password": "yourpassword" }
```

Response 200:
```json
{
  "access_token":  "<jwt>",
  "refresh_token": "<jwt>",
  "expires_in":    14400,
  "role":          "admin"
}
```

### POST /monitor/auth/refresh/

Request:
```json
{ "refresh_token": "<jwt>" }
```

Response 200: same shape as login response.

### POST /monitor/auth/logout/

No body required.  Response: `{ "status": "ok" }`

---

## Statistics

### GET /monitor/api/stats/

Returns aggregate counts, hourly trend (last 24 h), severity distribution, and
top attack types.

---

## Events

### GET /monitor/api/events/

Query parameters:

| Param | Type | Description |
|---|---|---|
| page | int | Page number (default 1) |
| per_page | int | Items per page (max 200, default 50) |
| severity | string | Filter: info / low / medium / high / critical |
| attack_type | string | Filter by attack type slug |
| session_id | uuid | Filter by session |
| start_date | ISO 8601 | Lower bound on timestamp |
| end_date | ISO 8601 | Upper bound on timestamp |
| search | string | Full-text search across path, body, IP |

Response shape:
```json
{
  "events": [ { "id": "...", "timestamp": "...", "attack_type": "...", ... } ],
  "pagination": { "page": 1, "per_page": 50, "total": 1234, "total_pages": 25 }
}
```

---

## Sessions

### GET /monitor/api/sessions/

Query parameters: `page`, `per_page`, `threat_level`, `is_blocked`, `country`.

### GET /monitor/api/sessions/{session_id}/

Full session detail including event timeline, captured credentials, and
deception interactions.

### POST /monitor/api/sessions/{session_id}/action/

Perform analyst actions.  Request body:

```json
{ "action": "block",    "reason": "Confirmed threat actor" }
{ "action": "unblock" }
{ "action": "add_tag",    "tag": "botnet" }
{ "action": "remove_tag", "tag": "botnet" }
{ "action": "add_note",   "note": "Correlated with TLP:WHITE IOC feed entry." }
```

---

## Credentials

### GET /monitor/api/credentials/

Returns paginated list of all captured credentials with analysis metadata
(strength, is_default, credential_type).

---

## Threat Intelligence

### GET /monitor/api/threat-intel/

Returns:
- 7-day daily trend with critical/high breakdown
- Top attack vectors with unique source counts
- Geographic distribution of attacker sessions
- Most common captured usernames
- Recent IOCs extracted from payloads

---

## Real-time Feed

### GET /monitor/api/realtime/?seconds=30

Returns events from the last N seconds.  Poll this endpoint at 5–10 s
intervals to power a live feed.

---

## Export

### POST /monitor/api/export/

Request:
```json
{ "type": "events", "format": "json" }
```

Valid types: `events`, `sessions`, `credentials`, `iocs`.
Valid formats: `json`, `csv`.

Response includes a `download_url` that expires after 1 hour.

---

## Health

### GET /api/health/

Unauthenticated.  Returns `{ "status": "ok", "timestamp": "..." }`.
Used by load balancer health probes and Kubernetes liveness checks.
