# TrapVault
## Professional-Grade Adaptive Deception & Automated Threat Orchestration

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![Django](https://img.shields.io/badge/Django-5.0+-green.svg)](https://djangoproject.com)
[![React](https://img.shields.io/badge/React-18+-61DAFB.svg)](https://reactjs.org)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Executive Summary

A **next-generation cybersecurity platform** combining high-fidelity deception, ML-powered anomaly detection, real-time threat intelligence enrichment, and automated incident response (SOAR). Built for academic research and professional security operations.

### Key Features

- **ML Anomaly Detection** — Isolation Forest behavioral profiling
- **Threat Intel Enrichment** — Real-time AbuseIPDB + GeoIP integration
- **SOAR Automation** — Auto-block high-threat actors
- **Dual-Environment Architecture** — Cryptographically separated Real vs. Deception
- **SOC-Grade SIEM** — Professional security operations dashboard
- **High-Fidelity Honeypot** — Indistinguishable from production banking app

---

## Architecture

```
                      NGINX (Reverse Proxy)
                   SSL/TLS + Security Headers
                            │
              ┌─────────────┴─────────────┐
              │                           │
              ▼                           ▼
     ┌──────────────────┐        ┌──────────────────┐
     │  REAL BANK       │        │  HONEYPOT        │
     │  (Legitimate)    │        │  (Deception)     │
     │ • Clean UI       │        │ • High Fidelity  │
     │ • Real Tx        │        │ • Data Poisoning │
     │ • Secure Auth    │        │ • ML Detection   │
     └──────────────────┘        └──────────────────┘
              │                           │
              └─────────────┬─────────────┘
                            ▼
              ┌──────────────────────────┐
              │  SIEM + ML ENGINE        │
              │ • Threat Scoring         │
              │ • Anomaly Detection      │
              │ • Pattern Matching       │
              │ • Intel Enrichment       │
              └──────────────────────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
         ┌────────┐   ┌────────┐   ┌────────┐
         │ Redis  │   │Postgres│   │ SOAR   │
         │ Cache  │   │  DB    │   │ Engine │
         └────────┘   └────────┘   └────────┘
```

---

## Quick Start

### Prerequisites
- Docker 24.0+
- Docker Compose 2.20+
- 4GB RAM minimum

### Installation

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/TrapVault.git
cd TrapVault

# Configure environment
cp .env.example .env
nano .env

# Build and start
docker-compose up -d --build

# Initialize database
docker-compose exec backend python manage.py migrate
docker-compose exec backend python manage.py seed_real_users
docker-compose exec backend python manage.py create_monitor_user
docker-compose exec backend python manage.py train_ml_model

# Access the platform
# Real Bank:  http://localhost/real-bank/
# Honeypot:   http://localhost/
# SIEM:       http://localhost/monitor/siem/
```

### Default Credentials

**Real Bank Users:**
- Alice: `alice` / `SecurePass123!`
- Bob: `bob` / `SecurePass456!`

**Monitor Dashboard:**
- Admin: `admin` / `change_this_password`

---

## Testing Attack Scenarios

### SQL Injection
```bash
curl -X POST http://localhost/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR 1=1--","password":"anything"}'
```

### Path Traversal
```bash
curl "http://localhost/api/files?path=../../../../etc/passwd"
```

### Brute Force
```bash
for i in {1..10}; do
  curl -X POST http://localhost/auth/login/ \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"wrong$i\"}"
done
```

### XSS Payload
```bash
curl -X POST http://localhost/api/search \
  -H "Content-Type: application/json" \
  -d '{"query":"<script>alert(document.cookie)</script>"}'
```

**Expected Behavior:**
- Threat score increases with each attack
- Session appears in SIEM dashboard
- ML model flags behavioral anomalies
- Auto-block triggers at score > 150
- Threat intel enrichment shows attacker location/ISP

---

## Project Structure

```
TrapVault/
├── backend/
│   ├── core/
│   │   ├── middleware.py          # WAF + Attack Detection
│   │   ├── models.py             # Django ORM Models
│   │   ├── views_proxy.py        # Dual-environment routing
│   │   ├── views_deception.py    # Honeypot responses
│   │   ├── views_real_bank.py    # Legitimate banking
│   │   ├── siem/                 # SIEM engine, signatures, ML, threat intel
│   │   └── soar/                 # SOAR automation
│   ├── honeypot/                 # Django project config
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   ├── components/
│   │   └── api/
│   ├── package.json
│   └── vite.config.ts
├── monitoring/
│   ├── grafana/dashboards/
│   └── prometheus/
├── scripts/
├── docs/
├── docker-compose.yml
├── .env.example
├── Makefile
└── README.md
```

---

## Configuration

### Environment Variables

```bash
# Database
POSTGRES_DB=honeypot
POSTGRES_USER=honeypot
POSTGRES_PASSWORD=your-secure-password

# Redis
REDIS_PASSWORD=your-redis-password

# Threat Intelligence
ABUSEIPDB_API_KEY=your-abuseipdb-key

# SIEM Thresholds
SIEM_DECEIVE_THRESHOLD=45
SIEM_BLOCK_THRESHOLD=120

# Alerts
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

### SIEM Tuning

Edit `backend/honeypot/settings.py`:

```python
HONEYPOT_CONFIG = {
    'THREAT_WEIGHTS': {
        'sql_injection': 30,
        'xss': 25,
        'command_injection': 40,
        'path_traversal': 35,
    },
    'AUTO_BLOCK_THRESHOLD': 150,
    'RATE_LIMIT_REQUESTS': 500,
}
```

---

## Monitoring

### Grafana Dashboards

Access at `http://localhost:3001`

**Pre-configured dashboards:**
1. **SIEM Overview** — Real-time attack metrics
2. **Threat Geo Map** — Global attacker distribution
3. **ML Anomaly Scores** — Behavioral analysis charts
4. **SOAR Actions** — Automated response timeline

### Prometheus Metrics

Key metrics:
- `honeypot_attacks_total` — Attack counter by type
- `honeypot_sessions_active` — Live attacker sessions
- `honeypot_threat_score` — Average threat score
- `honeypot_ml_anomaly_rate` — ML detection rate
- `honeypot_soar_blocks_total` — Auto-block counter

---


## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

```bash
git clone https://github.com/YOUR_USERNAME/TrapVault.git
cd TrapVault
git checkout -b feature/amazing-feature
docker-compose up --build
git push origin feature/amazing-feature
```

---

## License

MIT License — see [LICENSE](LICENSE) for details

---

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting guidelines.

---

**Built for Cybersecurity Research**
