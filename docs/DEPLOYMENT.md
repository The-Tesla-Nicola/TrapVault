# Deployment Guide

## Overview

This guide covers deployment of the Enterprise Honeypot + SIEM platform to production environments.

## Prerequisites

- Docker 24.0+
- Docker Compose 2.20+
- 4GB RAM minimum
- Ports 80, 443, 8000, 5432, 6379 available

## Environment Setup

### 1. Clone and Configure

```bash
git clone https://github.com/yourusername/enterprise-honeypot-pro.git
cd enterprise-honeypot-pro

# Copy environment template
cp .env.example .env

# Generate secrets
python -c "import secrets; print(secrets.token_hex(50))"
# Add to SECRET_KEY in .env
```

### 2. Configure SSL/TLS

For production, obtain SSL certificates:

```bash
# Using Let's Encrypt (automatic)
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com

# Or manually place certificates in ./certs/
# server.crt
# server.key
```

### 3. Build and Start

```bash
docker-compose up -d --build

# Initialize database
docker-compose exec backend python manage.py migrate
docker-compose exec backend python manage.py create_monitor_user admin P@ssw0rd! --role admin
docker-compose exec backend python manage.py seed_real_users
docker-compose exec backend python manage.py train_ml_model
```

## Production Checklist

- [ ] Change all default passwords
- [ ] Enable HTTPS with valid SSL certificates
- [ ] Restrict ALLOWED_HOSTS to actual domains
- [ ] Set DEBUG=False
- [ ] Use strong SECRET_KEY (50+ characters)
- [ ] Enable database backups
- [ ] Configure Slack/email alerts
- [ ] Enable fail2ban
- [ ] Configure log rotation

## Firewall Configuration

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 22/tcp  # SSH
sudo ufw enable
```

## Monitoring

- SIEM Dashboard: http://localhost/monitor/
- Grafana: http://localhost:3001
- Prometheus: http://localhost:9090

## Backup

```bash
# Database backup
./scripts/backup/backup-database.sh

# Restore
./scripts/backup/restore-database.sh backup.sql.gz
```

## Troubleshooting

See [OPERATIONS.md](OPERATIONS.md) for common issues and solutions.