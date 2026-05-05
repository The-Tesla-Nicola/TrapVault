#!/usr/bin/env bash
# =============================================================================
# Endpoint Health Check Script
# Tests every endpoint in the Enterprise Honeypot + SIEM system.
# Run after: make build && make up && make setup
#
# Usage:
#   chmod +x scripts/check_endpoints.sh
#   ./scripts/check_endpoints.sh
#   ./scripts/check_endpoints.sh http://your-domain.com
# =============================================================================

BASE_URL="${1:-http://localhost}"
MONITOR_USER="cyber_admin"
MONITOR_PASS="CyB3r_P@ssw0rd!99"
PASS=0
FAIL=0
WARN=0

# ── Colours ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
ok()   { echo -e "  ${GREEN}PASS${NC}  $1"; ((PASS++)); }
fail() { echo -e "  ${RED}FAIL${NC}  $1"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}WARN${NC}  $1"; ((WARN++)); }
hdr()  { echo -e "\n${BOLD}${CYAN}=== $1 ===${NC}"; }

# Check: HTTP status code matches expected
check() {
    local label="$1"
    local expected_status="$2"
    local method="$3"
    local url="$4"
    shift 4
    # Remaining args passed to curl

    local response
    response=$(curl -s -o /tmp/hp_response.json -w "%{http_code}" \
        -X "$method" "$url" "$@" --max-time 15 2>/dev/null)

    if [ "$response" = "$expected_status" ]; then
        ok "$label  [HTTP $response]"
        return 0
    else
        fail "$label  [expected $expected_status, got $response]"
        if [ -s /tmp/hp_response.json ]; then
            echo "       $(head -c 200 /tmp/hp_response.json)"
        fi
        return 1
    fi
}

# Check: response body contains a string
check_body() {
    local label="$1"
    local expected_status="$2"
    local method="$3"
    local url="$4"
    local body_contains="$5"
    shift 5

    local response
    response=$(curl -s -o /tmp/hp_response.json -w "%{http_code}" \
        -X "$method" "$url" "$@" --max-time 15 2>/dev/null)

    if [ "$response" = "$expected_status" ]; then
        if grep -q "$body_contains" /tmp/hp_response.json 2>/dev/null; then
            ok "$label  [HTTP $response, body contains '$body_contains']"
            return 0
        else
            fail "$label  [HTTP $response but body missing '$body_contains']"
            echo "       $(head -c 300 /tmp/hp_response.json)"
            return 1
        fi
    else
        fail "$label  [expected $expected_status, got $response]"
        return 1
    fi
}

# ── Step 0: Wait for backend ──────────────────────────────────────────────────
hdr "0. Waiting for backend to be ready"
MAX_WAIT=60
WAITED=0
until curl -sf "$BASE_URL/api/health/" > /dev/null 2>&1; do
    sleep 2
    WAITED=$((WAITED + 2))
    echo "  Waiting... ${WAITED}s"
    if [ $WAITED -ge $MAX_WAIT ]; then
        echo -e "  ${RED}Backend did not become ready within ${MAX_WAIT}s. Is the stack running?${NC}"
        echo "  Run: make up && make setup"
        exit 1
    fi
done
echo -e "  ${GREEN}Backend is up.${NC}"

# ── Step 1: Health check ──────────────────────────────────────────────────────
hdr "1. Health & Static"

check_body \
    "Health check" \
    "200" "GET" "$BASE_URL/api/health/" \
    "ok"

check \
    "Honeypot frontend (React SPA)" \
    "200" "GET" "$BASE_URL/"

check \
    "Real site" \
    "200" "GET" "$BASE_URL/real-site/"

# ── Step 2: Auth proxy – legitimate login ────────────────────────────────────
hdr "2. Transparent Auth Proxy"

check_body \
    "GET /api/auth/login/ (metadata)" \
    "200" "GET" "$BASE_URL/api/auth/login/" \
    "SecureBank"

check_body \
    "POST /api/auth/login/ – real customer (michael.scott)" \
    "200" "POST" "$BASE_URL/api/auth/login/" \
    "success" \
    -H "Content-Type: application/json" \
    -d '{"username":"michael.scott","password":"Michael$c0tt!123"}'

check_body \
    "POST /api/auth/login/ – wrong password (real user, should 401)" \
    "401" "POST" "$BASE_URL/api/auth/login/" \
    "error" \
    -H "Content-Type: application/json" \
    -d '{"username":"michael.scott","password":"wrongpassword"}'

check_body \
    "POST /api/auth/login/ – SQL injection (should DECEIVE, 500 error fragment)" \
    "500" "POST" "$BASE_URL/api/auth/login/" \
    "database" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin'"'"' OR 1=1--","password":"x"}'

check_body \
    "POST /api/auth/login/ – default creds admin/admin (should DECEIVE, fake JWT)" \
    "200" "POST" "$BASE_URL/api/auth/login/" \
    "access_token" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin"}'

check_body \
    "POST /api/auth/login/ – unknown user (should 401)" \
    "401" "POST" "$BASE_URL/api/auth/login/" \
    "error" \
    -H "Content-Type: application/json" \
    -d '{"username":"nobody","password":"nobody"}'

# ── Step 3: Honeypot deception traps ─────────────────────────────────────────
hdr "3. Honeypot Deception Endpoints"

check_body \
    "GET  /api/admin/dashboard/" \
    "401" "GET" "$BASE_URL/api/admin/dashboard/" \
    "Authentication"

check_body \
    "GET  /api/admin/users/" \
    "200" "GET" "$BASE_URL/api/admin/users/" \
    "data"

check_body \
    "GET  /api/admin/settings/" \
    "200" "GET" "$BASE_URL/api/admin/settings/" \
    "config"

check_body \
    "GET  /api/admin/backup/" \
    "200" "GET" "$BASE_URL/api/admin/backup/" \
    "backups"

check_body \
    "GET  /api/admin/api-keys/" \
    "200" "GET" "$BASE_URL/api/admin/api-keys/" \
    "api_keys"

check_body \
    "POST /api/admin/database/ (fake SQL console)" \
    "200" "POST" "$BASE_URL/api/admin/database/" \
    "query_executed" \
    -H "Content-Type: application/json" \
    -d '{"query":"SELECT * FROM users LIMIT 10"}'

check_body \
    "GET  /api/admin/files/ (fake file browser)" \
    "200" "GET" "$BASE_URL/api/admin/files/" \
    "files"

check_body \
    "GET  /api/admin/download/ (fake .env)" \
    "200" "GET" "$BASE_URL/api/admin/download/?file=.env" \
    "content"

check_body \
    "GET  /api/admin/download/ – path traversal attempt (should 403)" \
    "403" "GET" "$BASE_URL/api/admin/download/?file=../../../etc/passwd" \
    "error"

check_body \
    "GET  /api/internal/config/ (fake secrets dump)" \
    "200" "GET" "$BASE_URL/api/internal/config/" \
    "database"

check_body \
    "GET  /api/search/?q=test (reflects query)" \
    "200" "GET" "$BASE_URL/api/search/?q=test" \
    "test"

check_body \
    "POST /api/search/ – XSS attempt (should reflect, log attack)" \
    "200" "POST" "$BASE_URL/api/search/" \
    "results" \
    -H "Content-Type: application/json" \
    -d '{"q":"<script>alert(1)</script>"}'

check_body \
    "POST /api/password-reset/ (captures email)" \
    "200" "POST" "$BASE_URL/api/password-reset/" \
    "success" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com"}'

check_body \
    "GET  /api/auth/verify/ (fake MFA)" \
    "401" "POST" "$BASE_URL/api/auth/verify/" \
    "Invalid" \
    -H "Content-Type: application/json" \
    -d '{"code":"111111","mfa_token":"abc"}'

# ── Step 4: Common scanner targets ────────────────────────────────────────────
hdr "4. Common Scanner / Recon Trap Paths"

check_body \
    "GET  /.env trap" \
    "200" "GET" "$BASE_URL/api/.env" \
    "content"

check_body \
    "GET  /.git/config trap" \
    "200" "GET" "$BASE_URL/api/.git/config" \
    "content"

check_body \
    "GET  /wp-admin/ trap" \
    "401" "GET" "$BASE_URL/api/wp-admin/" \
    "Authentication"

check_body \
    "GET  /phpmyadmin/ trap" \
    "200" "GET" "$BASE_URL/api/phpmyadmin/" \
    "query_executed"

check_body \
    "GET  /actuator/ trap (Spring Boot scanner)" \
    "200" "GET" "$BASE_URL/api/actuator/" \
    "config"

check_body \
    "GET  /api/nonexistent/path/ (catch-all)" \
    "404" "GET" "$BASE_URL/api/nonexistent/completely/random/path/" \
    "available_endpoints"

# ── Step 5: Monitor auth ──────────────────────────────────────────────────────
hdr "5. Monitor Authentication"

check_body \
    "POST /monitor/auth/login/ – valid credentials" \
    "200" "POST" "$BASE_URL/monitor/auth/login/" \
    "access_token" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$MONITOR_USER\",\"password\":\"$MONITOR_PASS\"}"

# Extract token for subsequent requests
MONITOR_TOKEN=$(curl -s -X POST "$BASE_URL/monitor/auth/login/" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$MONITOR_USER\",\"password\":\"$MONITOR_PASS\"}" \
    | grep -o '"access_token":"[^"]*"' \
    | cut -d'"' -f4)

if [ -z "$MONITOR_TOKEN" ]; then
    warn "Could not extract monitor token – subsequent authenticated checks may fail"
    warn "Check: make create-user USER=admin PASS='AdminPass1!' ROLE=admin"
else
    echo -e "  ${GREEN}Token obtained:${NC} ${MONITOR_TOKEN:0:30}..."
fi

check_body \
    "POST /monitor/auth/login/ – wrong password (should 401)" \
    "401" "POST" "$BASE_URL/monitor/auth/login/" \
    "Invalid" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrongpassword"}'

check \
    "GET  /monitor/auth/login/ without token (should redirect or 401)" \
    "302" "GET" "$BASE_URL/monitor/" \
    -L

# ── Step 6: Monitor HTML pages ────────────────────────────────────────────────
hdr "6. Monitor HTML Pages"

check \
    "GET  /monitor/login/ (login page HTML)" \
    "200" "GET" "$BASE_URL/monitor/login/"

if [ -n "$MONITOR_TOKEN" ]; then
    check \
        "GET  /monitor/siem/ (SIEM dashboard HTML, with token cookie)" \
        "200" "GET" "$BASE_URL/monitor/siem/" \
        -H "Cookie: monitor_token=$MONITOR_TOKEN"
fi

# ── Step 7: Honeypot data API (authenticated) ─────────────────────────────────
hdr "7. Honeypot Data API (authenticated)"

if [ -n "$MONITOR_TOKEN" ]; then
    AUTH_HEADER="Authorization: Bearer $MONITOR_TOKEN"

    check_body \
        "GET  /monitor/api/stats/" \
        "200" "GET" "$BASE_URL/monitor/api/stats/" \
        "totals" \
        -H "$AUTH_HEADER"

    check_body \
        "GET  /monitor/api/events/" \
        "200" "GET" "$BASE_URL/monitor/api/events/" \
        "events" \
        -H "$AUTH_HEADER"

    check_body \
        "GET  /monitor/api/sessions/" \
        "200" "GET" "$BASE_URL/monitor/api/sessions/" \
        "sessions" \
        -H "$AUTH_HEADER"

    check_body \
        "GET  /monitor/api/credentials/" \
        "200" "GET" "$BASE_URL/monitor/api/credentials/" \
        "credentials" \
        -H "$AUTH_HEADER"

    check_body \
        "GET  /monitor/api/threat-intel/" \
        "200" "GET" "$BASE_URL/monitor/api/threat-intel/" \
        "summary" \
        -H "$AUTH_HEADER"

    check_body \
        "GET  /monitor/api/realtime/" \
        "200" "GET" "$BASE_URL/monitor/api/realtime/" \
        "events" \
        -H "$AUTH_HEADER"

else
    warn "Skipping authenticated honeypot API checks (no token)"
fi

# ── Step 8: SIEM API (authenticated) ──────────────────────────────────────────
hdr "8. SIEM API (authenticated)"

if [ -n "$MONITOR_TOKEN" ]; then
    AUTH_HEADER="Authorization: Bearer $MONITOR_TOKEN"

    check_body \
        "GET  /monitor/api/siem/overview/" \
        "200" "GET" "$BASE_URL/monitor/api/siem/overview/" \
        "kpis" \
        -H "$AUTH_HEADER"

    check_body \
        "GET  /monitor/api/siem/live/" \
        "200" "GET" "$BASE_URL/monitor/api/siem/live/" \
        "events" \
        -H "$AUTH_HEADER"

    check_body \
        "GET  /monitor/api/siem/alerts/" \
        "200" "GET" "$BASE_URL/monitor/api/siem/alerts/" \
        "alerts" \
        -H "$AUTH_HEADER"

    check_body \
        "GET  /monitor/api/siem/funnel/" \
        "200" "GET" "$BASE_URL/monitor/api/siem/funnel/?hours=24" \
        "by_outcome" \
        -H "$AUTH_HEADER"

    check_body \
        "GET  /monitor/api/siem/heatmap/" \
        "200" "GET" "$BASE_URL/monitor/api/siem/heatmap/?days=30" \
        "matrix" \
        -H "$AUTH_HEADER"

    check_body \
        "GET  /monitor/api/siem/iocs/" \
        "200" "GET" "$BASE_URL/monitor/api/siem/iocs/?hours=48" \
        "iocs" \
        -H "$AUTH_HEADER"

    check_body \
        "GET  /monitor/api/siem/rules/" \
        "200" "GET" "$BASE_URL/monitor/api/siem/rules/" \
        "rules" \
        -H "$AUTH_HEADER"

    check_body \
        "GET  /monitor/api/siem/real-users/" \
        "200" "GET" "$BASE_URL/monitor/api/siem/real-users/" \
        "users" \
        -H "$AUTH_HEADER"

    # Unauthenticated access to protected SIEM endpoints must fail
    check \
        "GET  /monitor/api/siem/overview/ without token (must be 401)" \
        "401" "GET" "$BASE_URL/monitor/api/siem/overview/"

    check \
        "GET  /monitor/api/stats/ without token (must be 401)" \
        "401" "GET" "$BASE_URL/monitor/api/stats/"

else
    warn "Skipping SIEM API checks (no token)"
fi

# ── Step 9: Security headers ───────────────────────────────────────────────────
hdr "9. Security Headers"

HEADERS=$(curl -sI "$BASE_URL/" 2>/dev/null)

for hname in "X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection"; do
    if echo "$HEADERS" | grep -qi "$hname"; then
        ok "Header present: $hname"
    else
        warn "Header missing: $hname  (check nginx.conf)"
    fi
done

# ── Step 10: Infrastructure ────────────────────────────────────────────────────
hdr "10. Infrastructure Services"

check_body \
    "Prometheus metrics page" \
    "200" "GET" "http://localhost:9090/-/healthy" \
    "Prometheus"

GRAFANA_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    http://localhost:3001/api/health --max-time 5 2>/dev/null)
if [ "$GRAFANA_STATUS" = "200" ]; then
    ok "Grafana health  [HTTP 200]"
    ((PASS++))
else
    warn "Grafana  [HTTP $GRAFANA_STATUS] – may not be started yet"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL + WARN))
echo ""
echo -e "${BOLD}════════════════════════════════════════${NC}"
echo -e "${BOLD}  Endpoint Check Summary${NC}"
echo -e "${BOLD}════════════════════════════════════════${NC}"
echo -e "  Total checked : $TOTAL"
echo -e "  ${GREEN}Passed${NC}        : $PASS"
echo -e "  ${YELLOW}Warnings${NC}      : $WARN"
echo -e "  ${RED}Failed${NC}        : $FAIL"
echo ""

if [ $FAIL -eq 0 ] && [ $WARN -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}ALL CHECKS PASSED — system is fully operational.${NC}"
    exit 0
elif [ $FAIL -eq 0 ]; then
    echo -e "  ${YELLOW}${BOLD}Passed with warnings — check items marked WARN above.${NC}"
    exit 0
else
    echo -e "  ${RED}${BOLD}$FAIL check(s) FAILED — review output above.${NC}"
    echo ""
    echo "  Common fixes:"
    echo "    make up          – start the stack"
    echo "    make setup       – run migrations + seed data"
    echo "    make logs        – view service logs"
    echo "    make ps          – check container status"
    exit 1
fi
