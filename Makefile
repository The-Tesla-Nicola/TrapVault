.PHONY: help build up down restart logs shell-backend shell-db \
        migrate makemigrations create-user seed-users seed-rules reset-db \
        test test-backend lint format security-scan \
        backup restore deploy-dev deploy-staging deploy-prod \
        clean clean-all init update ps stats

COMPOSE := $(shell docker compose version > /dev/null 2>&1 && echo "docker compose" || echo "docker-compose")

help:
	@printf "\nTrapVault — available targets\n\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  %-24s %s\n", $$1, $$2}'
	@printf "\n"

build: ## Build all Docker images
	$(COMPOSE) build

up: ## Start all services (detached)
	$(COMPOSE) up -d
	@printf "\n  Honeypot (attacker view) : http://localhost\n"
	@printf "  SIEM Dashboard           : http://localhost/monitor/siem/\n"
	@printf "  Grafana                  : http://localhost:3001\n"
	@printf "  Prometheus               : http://localhost:9090\n\n"

down: ## Stop and remove containers
	$(COMPOSE) down

restart: down up ## Restart all services

logs: ## Tail all service logs
	$(COMPOSE) logs -f

logs-backend: ## Tail backend logs only
	$(COMPOSE) logs -f backend

shell-backend: ## Open Django shell
	$(COMPOSE) exec backend python manage.py shell

shell-db: ## Open psql shell
	$(COMPOSE) exec postgres psql -U honeypot -d honeypot

ps: ## Show running containers
	$(COMPOSE) ps

stats: ## Show container resource usage
	docker stats

migrate: ## Run Django migrations
	$(COMPOSE) exec backend python manage.py migrate

makemigrations: ## Create new migrations
	$(COMPOSE) exec backend python manage.py makemigrations

create-user: ## Create monitor user  [USER=admin PASS=secret ROLE=admin]
	$(COMPOSE) exec backend python manage.py create_monitor_user \
	  $(USER) $(PASS) --role $(or $(ROLE),analyst)

seed-users: ## Seed demo legitimate bank users (dev/staging only)
	$(COMPOSE) exec backend python manage.py seed_real_users

seed-rules: ## Seed default SIEM alert rules
	$(COMPOSE) exec backend python manage.py seed_alert_rules

reset-db: ## DESTRUCTIVE: drop and recreate the database
	@printf "WARNING: All data will be lost. Press Ctrl-C to abort (5 s).\n"; sleep 5
	$(COMPOSE) down -v
	$(COMPOSE) up -d postgres
	@sleep 8
	$(COMPOSE) exec backend python manage.py migrate

setup: ## Complete first-time setup: migrate + admin user + seed data
	$(COMPOSE) exec backend python manage.py migrate
	$(COMPOSE) exec backend python manage.py create_monitor_user admin CHANGE_THIS_PASSWORD --role admin
	$(COMPOSE) exec backend python manage.py seed_real_users
	$(COMPOSE) exec backend python manage.py seed_alert_rules
	@printf "\n  Setup complete.\n"
	@printf "  SIEM login: http://localhost/monitor/siem/  (admin / CHANGE_THIS_PASSWORD)\n\n"

lint: ## Run Python (flake8) and JS (eslint) linters
	$(COMPOSE) exec backend flake8 .
	$(COMPOSE) exec backend black --check .

format: ## Auto-format Python source with black
	$(COMPOSE) exec backend black .

test: ## Run all tests
	$(COMPOSE) exec backend pytest --cov=. --cov-report=term-missing

security-scan: ## Scan with Trivy + Bandit
	trivy image trapvault-backend:latest
	$(COMPOSE) exec backend bandit -r . -x ./venv,./tests -f json -o /tmp/bandit.json || true

backup: ## Backup PostgreSQL database
	./scripts/backup/backup-database.sh

restore: ## Restore from backup  [BACKUP=path/to/file.sql.gz]
	./scripts/backup/restore-database.sh $(BACKUP)

deploy-dev: ## Deploy to development Kubernetes overlay
	kubectl apply -k infrastructure/kubernetes/overlays/dev

deploy-staging: ## Deploy to staging Kubernetes overlay
	kubectl apply -k infrastructure/kubernetes/overlays/staging

deploy-prod: ## Deploy to production Kubernetes overlay (confirms)
	@printf "WARNING: Deploying to PRODUCTION. Ctrl-C to abort (5 s).\n"; sleep 5
	kubectl apply -k infrastructure/kubernetes/overlays/production

ssl: ## Obtain Let's Encrypt cert  [DOMAIN=x EMAIL=y]
	./scripts/deployment/setup-ssl.sh $(DOMAIN) $(EMAIL)

clean: ## Remove containers, volumes, build caches
	$(COMPOSE) down -v --remove-orphans
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf backend/staticfiles frontend/dist

clean-all: clean ## Deep clean including node_modules
	rm -rf frontend/node_modules backend/venv

init: ## Initialise project from scratch
	@cp -n .env.example .env || true
	@printf "Copied .env.example -> .env\n"
	cd frontend && npm install
	cd backend && python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt
	@printf "\nEdit .env, then run: make build up setup\n"

update: ## Update Python and JS dependencies
	cd backend && pip install -r requirements.txt --upgrade
	cd frontend && npm update
