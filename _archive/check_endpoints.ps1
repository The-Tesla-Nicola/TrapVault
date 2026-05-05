# =============================================================================
# Endpoint Health Check (PowerShell Version)
# =============================================================================

$BaseUrl = "http://localhost"
$MonitorUser = "cyber_admin"
$MonitorPass = "CyB3r_P@ssw0rd!99"
$script:Pass = 0
$script:Fail = 0

function Test-Endpoint {
    param($Label, $Method, $Url, $ExpectedStatus, $BodyContains, $Body)
    
    $params = @{
        Uri = $Url
        Method = $Method
        ContentType = "application/json"
        ErrorAction = "SilentlyContinue"
        UseBasicParsing = $true
    }
    if ($Body) { $params.Body = $Body }

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

Write-Host "`n=== 2. Transparent Auth Proxy ===" -ForegroundColor Cyan
Test-Endpoint "Legitimate login (michael)" "Post" "$BaseUrl/api/auth/login/" 200 "success" '{"username":"michael.scott","password":"Michael$c0tt!123"}'
# Note: SQLi might return 401 if threshold/confidence isn't high enough for immediate 500
Test-Endpoint "SQL injection attempt (High-Conf)" "Post" "$BaseUrl/api/auth/login/" 500 "database" '{"username":"admin\" UNION SELECT 1,2,SLEEP(5)--","password":"x"}'
Test-Endpoint "Default creds (admin/admin)" "Post" "$BaseUrl/api/auth/login/" 200 "access_token" '{"username":"admin","password":"admin"}'

Write-Host "`n=== 3. Honeypot Deception Traps ===" -ForegroundColor Cyan
Test-Endpoint "Fake user management" "Get" "$BaseUrl/api/admin/users/" 200 "data"
Test-Endpoint "Fake file browser" "Get" "$BaseUrl/api/admin/files/" 200 "files"
Test-Endpoint "Canary token download" "Get" "$BaseUrl/api/admin/download/?file=database_backup.sql.gz" 200 "content"

Write-Host "`n=== 4. Scanner Traps ===" -ForegroundColor Cyan
Test-Endpoint ".env trap" "Get" "$BaseUrl/api/.env" 200 "content"
Test-Endpoint "phpmyadmin trap" "Get" "$BaseUrl/api/phpmyadmin/" 200 "query_executed"

Write-Host "`n=== 5. Monitor Authentication ===" -ForegroundColor Cyan
$loginBody = @{ username = $MonitorUser; password = $MonitorPass } | ConvertTo-Json
try {
    $authRes = Invoke-RestMethod -Uri "$BaseUrl/monitor/auth/login/" -Method Post -ContentType "application/json" -Body $loginBody
    $token = $authRes.access_token
    if ($token) {
        Write-Host "  [PASS] Monitor Login & Token obtained" -ForegroundColor Green
        $script:Pass++
        
        Write-Host "`n=== 6. Authenticated SIEM API ===" -ForegroundColor Cyan
        $headers = @{ Authorization = "Bearer $token" }
        $res = Invoke-RestMethod -Uri "$BaseUrl/monitor/api/siem/overview/" -Method Get -Headers $headers
        if ($res.kpis) {
            Write-Host "  [PASS] SIEM API Overview" -ForegroundColor Green
            $script:Pass++
        } else {
            Write-Host "  [FAIL] SIEM API Overview (Missing KPIs)" -ForegroundColor Red
            $script:Fail++
        }
    } else {
        Write-Host "  [FAIL] Monitor Login (No token)" -ForegroundColor Red
        $script:Fail++
    }
} catch {
    Write-Host "  [FAIL] Monitor Login failed: $($_.Exception.Message)" -ForegroundColor Red
    $script:Fail++
}

Write-Host "`nSummary: $script:Pass Passed, $script:Fail Failed" -ForegroundColor Yellow
if ($script:Fail -gt 0) { exit 1 } else { exit 0 }
