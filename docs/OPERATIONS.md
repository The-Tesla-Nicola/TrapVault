# Operations Runbook

## First-time setup

```bash
# 1. Clone and initialise
git clone https://github.com/your-org/enterprise-honeypot-system.git
cd enterprise-honeypot-system
make init                         # copies .env.example -> .env, installs deps

# 2. Configure secrets
nano .env                         # set SECRET_KEY, POSTGRES_PASSWORD, MONITOR_JWT_SECRET

# 3. Build and start
make build
make up

# 4. Apply database migrations
make migrate

# 5. Create the first operator account
make create-user USER=admin PASS=YourSecurePassword123 ROLE=admin

# 6. Open monitor dashboard
open http://localhost/monitor/
```

## Daily operations

```bash
make logs          # stream all logs
make stats         # container CPU/RAM usage
make ps            # service health at a glance
```

## Create additional operator accounts

```bash
make create-user USER=analyst1 PASS=SecurePass1 ROLE=analyst
make create-user USER=viewer1  PASS=SecurePass2 ROLE=viewer
```

Role permissions:

| Permission | admin | analyst | viewer |
|---|---|---|---|
| view | yes | yes | yes |
| analyze (block/tag/note) | yes | yes | no |
| export | yes | yes | no |
| configure | yes | no | no |
| manage_users | yes | no | no |

## Database backup and restore

```bash
make backup                           # creates backups/honeypot_YYYYMMDD_HHMMSS.sql.gz
make restore BACKUP=backups/file.sql.gz
```

## Scaling

```bash
# Horizontal scale (Docker Compose)
docker compose up -d --scale backend=4

# Kubernetes
kubectl scale deployment honeypot-backend --replicas=8 -n honeypot-production
```

## Resetting a blocked attacker

```bash
# Via the monitor dashboard: Sessions -> find session -> Actions -> Unblock
# Or directly in Django admin: /django-admin/core/attackersession/
```

## Pruning old attack logs

By default logs are retained indefinitely. To prune via Django shell:

```python
from django.utils import timezone
from datetime import timedelta
from core.models import AttackEvent

cutoff = timezone.now() - timedelta(days=90)
count, _ = AttackEvent.objects.filter(timestamp__lt=cutoff).delete()
print(f"Deleted {count} events.")
```

## GeoIP enrichment

1. Register at https://dev.maxmind.com/geoip/geolite2-free/
2. Download `GeoLite2-City.mmdb`
3. Place it at `backend/geoip/GeoLite2-City.mmdb`
4. Set `GEOIP_PATH=/app/geoip/GeoLite2-City.mmdb` in `.env`
5. Restart: `make restart`

## Deploying to production (Railway + Vercel)

### Backend (Railway)

1. Push code to GitHub.
2. Create Railway project → Deploy from GitHub → select `backend/` as root.
3. Add PostgreSQL plugin; Railway injects `DATABASE_URL` automatically.
4. Set environment variables:
   - `SECRET_KEY` – long random string
   - `MONITOR_JWT_SECRET` – long random string
   - `DEBUG=False`
   - `ALLOWED_HOSTS=.railway.app,.vercel.app`
5. Run migrations: Railway → Settings → "Run Command" → `python manage.py migrate`

### Frontend (Vercel)

1. Set `VITE_API_URL=https://your-app.up.railway.app/api` in `frontend/.env.production`
2. `cd frontend && vercel --prod`
3. Add your Vercel domain to `CORS_ALLOWED_ORIGINS` in Railway env vars.

## Kubernetes production deployment

```bash
# Create namespace and secrets
kubectl create namespace honeypot-production
kubectl create secret generic honeypot-secrets \
  --from-literal=SECRET_KEY="..." \
  --from-literal=POSTGRES_PASSWORD="..." \
  --from-literal=MONITOR_JWT_SECRET="..." \
  -n honeypot-production

# Deploy
make deploy-prod

# Verify
kubectl get pods    -n honeypot-production
kubectl get svc     -n honeypot-production
kubectl get ingress -n honeypot-production
```

## Troubleshooting

| Symptom | Check |
|---|---|
| `database connection failed` | `docker compose logs postgres` |
| `redis connection error` | `docker compose exec redis redis-cli ping` |
| `monitor 401 Unauthorized` | Verify MONITOR_JWT_SECRET matches in .env and running container |
| Frontend blank page | `docker compose logs nginx`, ensure `frontend/dist/` exists |
| Attacks not appearing | Check middleware is listed in MIDDLEWARE in settings.py |
| GeoIP not resolving | Confirm GeoLite2-City.mmdb path and GEOIP_PATH env var |
