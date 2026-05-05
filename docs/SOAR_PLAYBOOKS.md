# SOAR Playbooks

## Overview

Security Orchestration, Automation, and Response (SOAR) playbooks automate incident response.

## Available Playbooks

### 1. Auto-Block High-Threat Actors

**Trigger**: Session threat score >= AUTO_BLOCK_THRESHOLD

**Actions**:
1. Flag session in Redis blacklist
2. Update Postgres `is_blocked` flag
3. Generate nginx blocklist.conf
4. Reload nginx (zero downtime)
5. Log as "Automated Mitigation"

**Configuration**:
```python
HONEYPOT_CONFIG = {
    'AUTO_BLOCK_THRESHOLD': 120,
}
```

### 2. Brute Force Detection

**Trigger**: SIEM_BRUTE_LIMIT failed logins per 10 minutes

**Actions**:
1. Flag session as brute force
2. Increase threat score
3. Send alert (Slack/email)

### 3. Burst Request Detection

**Trigger**: SIEM_BURST_LIMIT requests per minute

**Actions**:
1. Flag session as burst
2. Rate limit session
3. Log spike event

### 4. Threat Intel Enrichment

**Trigger**: First request from new IP

**Actions**:
1. Query AbuseIPDB
2. Query GeoIP
3. Update session metadata

## Manual Actions

### Block IP Manually

```bash
docker-compose exec backend python manage.py shell
>>> from core.models import AttackerSession
>>> session = AttackerSession.objects.get(ip_address='1.2.3.4')
>>> session.is_blocked = True
>>> session.save()
```

### Unblock IP

```bash
>>> session.is_blocked = False
>>> session.save()
```

## SOAR Logs

View automated actions:
```bash
docker-compose exec backend python manage.py shell
>>> from core.models import SOARAction
>>> SOARAction.objects.filter(automated=True).order_by('-created_at')[:10]
```

## Custom Playbooks

Add custom playbooks in `core/soar/playbooks.py`:

```python
def custom_playbook(session, trigger):
    # Your automation logic
    pass
```