#!/bin/bash
# =============================================================================
# Enterprise Honeypot + SIEM - Quick Start Script
# =============================================================================
# This script deploys the enhanced honeypot with ML, Threat Intel, and SOAR
# Usage: ./deploy.sh
# =============================================================================

set -e  # Exit on error

echo "=========================================="
echo "Enterprise Honeypot + SIEM Deployment"
echo "=========================================="
echo ""

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}✗ Docker is not running${NC}"
    echo "Please start Docker and try again"
    exit 1
fi
echo -e "${GREEN}✓ Docker is running${NC}"

# Check if docker-compose exists
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}✗ docker-compose not found${NC}"
    echo "Please install docker-compose and try again"
    exit 1
fi
echo -e "${GREEN}✓ docker-compose found${NC}"

# Create .env if it doesn't exist
if [ ! -f .env ]; then
    echo -e "${YELLOW}Creating .env file...${NC}"
    cp .env.example .env
    echo -e "${GREEN}✓ Created .env (please edit with your API keys)${NC}"
else
    echo -e "${GREEN}✓ .env file exists${NC}"
fi

# Create necessary directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p logs/nginx
mkdir -p backend/ml_models
mkdir -p backend/geoip
mkdir -p monitoring/grafana/provisioning
mkdir -p monitoring/prometheus/data
echo -e "${GREEN}✓ Directories created${NC}"

# Build containers
echo -e "${YELLOW}Building Docker containers...${NC}"
docker-compose build
echo -e "${GREEN}✓ Containers built${NC}"

# Start services
echo -e "${YELLOW}Starting services...${NC}"
docker-compose up -d
echo -e "${GREEN}✓ Services started${NC}"

# Wait for database to be ready
echo -e "${YELLOW}Waiting for database...${NC}"
sleep 10

# Run migrations
echo -e "${YELLOW}Running database migrations...${NC}"
docker-compose exec -T backend python manage.py migrate --noinput
echo -e "${GREEN}✓ Migrations complete${NC}"

# Create superuser
echo -e "${YELLOW}Creating monitor user...${NC}"
docker-compose exec -T backend python manage.py create_monitor_user || echo "Monitor user already exists"
echo -e "${GREEN}✓ Monitor user ready${NC}"

# Seed real users
echo -e "${YELLOW}Seeding real bank users...${NC}"
docker-compose exec -T backend python manage.py seed_real_users
echo -e "${GREEN}✓ Real users seeded (Alice and Bob)${NC}"

# Collect static files
echo -e "${YELLOW}Collecting static files...${NC}"
docker-compose exec -T backend python manage.py collectstatic --noinput
echo -e "${GREEN}✓ Static files collected${NC}"

# Train ML model (if enough data)
echo -e "${YELLOW}Training ML model (may skip if insufficient data)...${NC}"
docker-compose exec -T backend python manage.py train_ml_model || echo "ML training skipped - need more baseline data"

echo ""
echo "=========================================="
echo -e "${GREEN}✓ Deployment Complete!${NC}"
echo "=========================================="
echo ""
echo "Access your platform:"
echo "  🏦 Real Bank:    http://localhost/real-bank/"
echo "  🍯 Honeypot:     http://localhost/"
echo "  🛡️  SIEM:         http://localhost/monitor/siem/"
echo "  📊 Grafana:      http://localhost:3001"
echo ""
echo "Default Credentials:"
echo "  Real Bank Users:"
echo "    - alice / SecurePass123!"
echo "    - bob / SecurePass456!"
echo ""
echo "  Monitor Dashboard:"
echo "    - admin / change_this_password"
echo ""
echo "Next Steps:"
echo "  1. Edit .env with your AbuseIPDB API key"
echo "  2. Download GeoIP database to backend/geoip/"
echo "  3. Generate traffic to train ML model"
echo "  4. Run: docker-compose exec backend python manage.py train_ml_model"
echo ""
echo "To stop: docker-compose down"
echo "To view logs: docker-compose logs -f"
echo ""
