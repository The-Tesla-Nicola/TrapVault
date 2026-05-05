# =============================================================================
# Comprehensive Endpoint Health Check (PowerShell Translation)
# Covers all 10 steps from the provided bash script.
# =============================================================================

$BaseUrl = "http://localhost"
$MonitorUser = "cyber_admin"
$MonitorPass = "CyB3r_P@ssw0rd!99"
$script:Pass = 0
$script:Fail = 0
$script:Warn = 0

function Test-Endpoint {
    param($Label, $Method, $Url, $ExpectedStatus, $BodyContains, $Body, $Headers = @{})
    
    $params = @{
        Uri = $Url
        Method = $Method
        ContentType = "application/json"
        ErrorAction = "SilentlyContinue"
        UseBasicParsing = $true
        TimeoutSec = 15
    }
    if ($Body) { $params.Body = $Body }
    if ($Headers) { $params.Headers = $Headers }

    try {
        $response = Invoke-WebRequest @params
        $statusCode = [int]$response.StatusCode
        $content = $response.Content
        
        if ($statusCode -eq $ExpectedStatus) {
            if ($BodyContains -and $content -notmatch $BodyContains) {
                Write-Host "  [FAIL] $Label (HTTP $statusCode, but missing '$BodyContains')" -ForegroundColor Red
                $script:Fail++
            } else {
                Write-Host "  [PASS] $Label (HTTP $statusCode)" -ForegroundColor Green
                $script:Pass++
            }
        } else {
            Write-Host "  [FAIL] $Label (Expected $ExpectedStatus, got $statusCode)" -ForegroundColor Red
            $script:Fail++
        }
    } catch {
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            if ($statusCode -eq $ExpectedStatus) {
                Write-Host "  [PASS] $Label (HTTP $statusCode)" -ForegroundColor Green
                $script:Pass++
            } else {
                Write-Host "  [FAIL] $Label (Expected $ExpectedStatus, got $statusCode)" -ForegroundColor Red
                $script:Fail++
            }
        } else {
            Write-Host "  [FAIL] $Label (Connection error: $($_.Exception.Message))" -ForegroundColor Red
            $script:Fail++
        }
    }
}

Write-Host "`n=== 1. Health & Static ===" -ForegroundColor Cyan
Test-Endpoint "Health check" "Get" "$BaseUrl/api/health/" 200 "ok"
Test-Endpoint "Honeypot frontend" "Get" "$BaseUrl/" 200
Test-Endpoint "Real site" "Get" "$BaseUrl/real-site/" 200

Write-Host "`n=== 2. Transparent Auth Proxy ===" -ForegroundColor Cyan
Test-Endpoint "GET login metadata" "Get" "$BaseUrl/api/auth/login/" 200 "SecureBank"
Test-Endpoint "Legitimate login (michael)" "Post" "$BaseUrl/api/auth/login/" 200 "success" '{"username":"michael.scott","password":"Michael$c0tt!123"}'
Test-Endpoint "Wrong password (michael)" "Post" "$BaseUrl/api/auth/login/" 401 "error" '{"username":"michael.scott","password":"wrongpassword"}'
Test-Endpoint "SQL injection attempt" "Post" "$BaseUrl/api/auth/login/" 500 "database" '{"username":"admin\" UNION SELECT 1,2,SLEEP(5)--","password":"x"}'
Test-Endpoint "Default creds (admin/admin)" "Post" "$BaseUrl/api/auth/login/" 200 "access_token" '{"username":"admin","password":"admin"}'
Test-Endpoint "Unknown user" "Post" "$BaseUrl/api/auth/login/" 401 "error" '{"username":"nobody","password":"nobody"}'

Write-Host "`n=== 3. Honeypot Deception Traps ===" -ForegroundColor Cyan
Test-Endpoint "Admin Dashboard (should 401)" "Get" "$BaseUrl/api/admin/dashboard/" 401 "Authentication"
Test-Endpoint "Fake users" "Get" "$BaseUrl/api/admin/users/" 200 "data"
Test-Endpoint "Fake settings" "Get" "$BaseUrl/api/admin/settings/" 200 "config"
Test-Endpoint "Fake backup" "Get" "$BaseUrl/api/admin/backup/" 200 "backups"
Test-Endpoint "Fake API keys" "Get" "$BaseUrl/api/admin/api-keys/" 200 "api_keys"
Test-Endpoint "Fake SQL console" "Post" "$BaseUrl/api/admin/database/" 200 "query_executed" '{"query":"SELECT * FROM users"}'
Test-Endpoint "Fake file browser" "Get" "$BaseUrl/api/admin/files/" 200 "files"
Test-Endpoint "Fake download .env" "Get" "$BaseUrl/api/admin/download/?file=.env" 200 "content"
Test-Endpoint "Path traversal (should 403)" "Get" "$BaseUrl/api/admin/download/?file=../../../etc/passwd" 403 "error"
Test-Endpoint "Fake secrets dump" "Get" "$BaseUrl/api/internal/config/" 200 "database"
Test-Endpoint "XSS attempt" "Post" "$BaseUrl/api/search/" 200 "results" '{"q":"<script>alert(1)</script>"}'
Test-Endpoint "Password reset" "Post" "$BaseUrl/api/password-reset/" 200 "success" '{"email":"test@example.com"}'

Write-Host "`n=== 4. Scanner Traps ===" -ForegroundColor Cyan
Test-Endpoint ".env trap" "Get" "$BaseUrl/api/.env" 200 "content"
Test-Endpoint ".git/config trap" "Get" "$BaseUrl/api/.git/config" 200 "content"
Test-Endpoint "wp-admin trap" "Get" "$BaseUrl/api/wp-admin/" 401 "Authentication"
Test-Endpoint "phpmyadmin trap" "Get" "$BaseUrl/api/phpmyadmin/" 200 "query_executed"
Test-Endpoint "actuator trap" "Get" "$BaseUrl/api/actuator/" 200 "config"
Test-Endpoint "Catch-all 404" "Get" "$BaseUrl/api/nonexistent/path/" 404 "available_endpoints"

Write-Host "`n=== 5. Monitor Authentication ===" -ForegroundColor Cyan
$token = ""
$loginBody = @{ username = $MonitorUser; password = $MonitorPass } | ConvertTo-Json
try {
    $authRes = Invoke-RestMethod -Uri "$BaseUrl/monitor/auth/login/" -Method Post -ContentType "application/json" -Body $loginBody

    $token = $authRes.access_token
    if ($token) {
        Write-Host "  [PASS] Monitor Login & Token obtained" -ForegroundColor Green
        $script:Pass++
    } else {
        Write-Host "  [FAIL] Monitor Login (No token)" -ForegroundColor Red
        $script:Fail++
    }
} catch {
    Write-Host "  [FAIL] Monitor Login failed: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $respBody = $reader.ReadToEnd()
        Write-Host "  Response: $respBody" -ForegroundColor Gray
    }
    $script:Fail++
}

Write-Host "`n=== 6. Monitor HTML Pages ===" -ForegroundColor Cyan
Test-Endpoint "Monitor login page" "Get" "$BaseUrl/monitor/login/" 200
if ($token) {
    $headers = @{ Cookie = "monitor_token=$token" }
    Test-Endpoint "SIEM Dashboard HTML" "Get" "$BaseUrl/monitor/siem/" 200 $null $null $headers
}

Write-Host "`n=== 7. Honeypot Data API ===" -ForegroundColor Cyan
if ($token) {
    $authHeaders = @{ Authorization = "Bearer $token" }
    Test-Endpoint "Stats API" "Get" "$BaseUrl/monitor/api/stats/" 200 "totals" $null $authHeaders
    Test-Endpoint "Events API" "Get" "$BaseUrl/monitor/api/events/" 200 "events" $null $authHeaders
    Test-Endpoint "Sessions API" "Get" "$BaseUrl/monitor/api/sessions/" 200 "sessions" $null $authHeaders
}

Write-Host "`n=== 8. SIEM API ===" -ForegroundColor Cyan
if ($token) {
    Test-Endpoint "SIEM Overview" "Get" "$BaseUrl/monitor/api/siem/overview/" 200 "kpis" $null $authHeaders
    Test-Endpoint "SIEM Alerts" "Get" "$BaseUrl/monitor/api/siem/alerts/" 200 "alerts" $null $authHeaders
    Test-Endpoint "SIEM Rules" "Get" "$BaseUrl/monitor/api/siem/rules/" 200 "rules" $null $authHeaders
}

Write-Host "`n=== 9. Security Headers ===" -ForegroundColor Cyan
try {
    $resp = Invoke-WebRequest -Uri "$BaseUrl/" -Method Head -UseBasicParsing
    $headers = $resp.Headers
    foreach ($h in @("X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection")) {
        if ($headers.ContainsKey($h)) {
            Write-Host "  [PASS] Header present: $h" -ForegroundColor Green
            $script:Pass++
        } else {
            Write-Host "  [WARN] Header missing: $h" -ForegroundColor Yellow
            $script:Warn++
        }
    }
} catch {
    Write-Host "  [FAIL] Could not fetch headers" -ForegroundColor Red
    $script:Fail++
}

Write-Host "`n=== 10. Infrastructure ===" -ForegroundColor Cyan
Test-Endpoint "Prometheus Healthy" "Get" "http://localhost:9090/-/healthy" 200 "Prometheus"
Test-Endpoint "Grafana Healthy" "Get" "http://localhost:3001/api/health" 200

Write-Host "`nSummary: $script:Pass Passed, $script:Fail Failed, $script:Warn Warnings" -ForegroundColor Yellow
if ($script:Fail -gt 0) { exit 1 } else { exit 0 }
