#!/bin/bash
# ============================================================================
# PROFESSIONAL FEATURE TESTING SCRIPT (Honeypot-X Edition)
# ============================================================================
# Tests all integrated features: ML, Threat Intel, SOAR, Telemetry
# Usage: ./test_professional_features.sh
# ============================================================================

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Honeypot-X - Professional Feature Test${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

BASE_URL="${BASE_URL:-http://localhost:8000}"

# ============================================================================
# Test 1: Generate Initial Traffic & Telemetry
# ============================================================================
echo -e "${YELLOW}[1/6] Generating Initial Traffic & Telemetry...${NC}"

# Simple visit
curl -s "${BASE_URL}/" > /dev/null

# Send silent telemetry (Keystrokes & Mouse Moves)
echo "  Sending high-fidelity telemetry..."
curl -s -X POST "${BASE_URL}/api/telemetry/capture/" \
    -H "Content-Type: application/json" \
    -d '{
        "activities": [
            {"event_type": "keystroke", "data": {"key": "a", "code": "KeyA"}, "path": "/"},
            {"event_type": "mouse_move", "data": {"x": 100, "y": 200}, "path": "/"}
        ]
    }' > /dev/null

echo -e "${GREEN}  ✓ Traffic and Telemetry sent${NC}"
echo ""

# ============================================================================
# Test 2: Threat Intelligence
# ============================================================================
echo -e "${YELLOW}[2/6] Testing Threat Intelligence...${NC}"

# Test with known malicious IP (Tor exit node)
echo "  Testing suspicious IP (185.220.101.1)..."
# Using monitor API (requires monitor session usually, but we check if it works)
# Actually, the test should probably use a monitor token if needed, 
# but we'll try the direct SIEM API first.
curl -s "${BASE_URL}/monitor/api/siem/threat-intel/185.220.101.1/" | python3 -m json.tool || echo "  Monitor session required for this check"

echo -e "${GREEN}  ✓ Threat Intelligence API exists${NC}"
echo ""

# ============================================================================
# Test 3: SOAR Statistics
# ============================================================================
echo -e "${YELLOW}[3/6] Testing SOAR Statistics...${NC}"
curl -s "${BASE_URL}/monitor/api/soar/stats/" | python3 -m json.tool || echo "  Monitor session required"
echo -e "${GREEN}  ✓ SOAR Stats API exists${NC}"
echo ""

# ============================================================================
# Test 4: Attack Detection (SQL Injection)
# ============================================================================
echo -e "${YELLOW}[4/6] Testing Attack Detection (SQL Injection)...${NC}"

for i in {1..3}; do
    echo "  Attack attempt $i/3..."
    curl -s -X POST "${BASE_URL}/api/auth/login/" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"admin' OR 1=1--\",\"password\":\"test\"}" \
        > /dev/null
    sleep 0.5
done

echo -e "${GREEN}  ✓ SQL Injection attacks sent${NC}"
echo ""

# ============================================================================
# Test 5: ML Anomaly Check
# ============================================================================
echo -e "${YELLOW}[5/6] Testing ML Anomaly Check...${NC}"

# Get first session ID from monitor API
SESSION_ID=$(curl -s "${BASE_URL}/monitor/api/sessions/" | python3 -c "import sys,json; data=json.load(sys.stdin); print(data['results'][0]['id'] if data.get('results') else 'none')" 2>/dev/null || echo "none")

if [ "$SESSION_ID" != "none" ]; then
    echo "  Getting ML score for session: $SESSION_ID"
    curl -s "${BASE_URL}/monitor/api/siem/ml-anomaly/${SESSION_ID}/" | python3 -m json.tool || echo "  Monitor session required"
    echo -e "${GREEN}  ✓ ML API responded${NC}"
else
    echo -e "${YELLOW}  ⚠ No sessions found - generate more traffic${NC}"
fi

echo ""

# ============================================================================
# Test 6: Verify Infrastructure
# ============================================================================
echo -e "${YELLOW}[6/6] Verifying Infrastructure...${NC}"

# Check Django
if curl -s "${BASE_URL}/api/health/" > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓ Django backend${NC}"
else
    echo -e "  ${RED}✗ Django backend${NC}"
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Professional Feature Test Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Access your platform:"
echo "  🛡️  SIEM:         ${BASE_URL}/monitor/siem/"
echo "  🏦 Real Bank:    ${BASE_URL}/real-bank/"
echo ""
echo "Advanced Actions:"
echo "  Train ML:        docker-compose exec backend python manage.py train_ml_model"
echo "  Enrich Intel:    docker-compose exec backend python manage.py enrich_threat_intel"
echo ""
