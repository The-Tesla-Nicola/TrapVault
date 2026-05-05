#!/usr/bin/env python
"""Generate attack traffic for testing the honeypot"""

import os
import sys
import django
import random
import time

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "honeypot.settings")
django.setup()

import requests
from core.models import AttackerSession as AttackerSession

BASE_URL = "http://127.0.0.1:8000"
attacks = []

# 1. Brute Force Login Attempts
print("=== Brute Force ===")
passwords = ["password", "123456", "admin", "letmein", "qwerty", "12345678", "root"]
for pw in passwords[:5]:
    try:
        r = requests.post(
            f"{BASE_URL}/api/auth/login/",
            json={"username": "admin", "password": pw},
            timeout=5,
        )
        attacks.append(("Brute force", pw, r.status_code))
    except Exception as e:
        attacks.append(("Brute force", pw, str(e)[:20]))

# 2. SQL Injection Attempts
print("=== SQL Injection ===")
sqli_tests = [
    "admin' --",
    "admin' OR '1'='1",
    "admin UNION SELECT--",
    "' OR '1'='1' --",
]
for sql in sqli_tests:
    try:
        r = requests.post(
            f"{BASE_URL}/api/auth/login/",
            json={"username": sql, "password": "test"},
            timeout=5,
        )
        attacks.append(("SQLi", sql[:20], r.status_code))
    except Exception as e:
        attacks.append(("SQLi", sql[:20], str(e)[:20]))

# 3. Credential Stuffing
print("=== Credential Stuffing ===")
creds = [
    ("admin", "admin123"),
    ("admin", "password"),
    ("admin", "123456"),
    ("test", "test"),
    ("root", "root"),
]
for u, p in creds:
    try:
        r = requests.post(
            f"{BASE_URL}/api/auth/login/",
            json={"username": u, "password": p},
            timeout=5,
        )
        attacks.append(("Stuffing", f"{u}:{p}", r.status_code))
    except Exception as e:
        attacks.append(("Stuffing", f"{u}:{p}", str(e)[:20]))

# 4. Burst Requests (to trigger rate limiting)
print("=== Burst Detection ===")
for i in range(25):
    try:
        r = requests.get(
            f"{BASE_URL}/api/telemetry/capture/", json={"test": i}, timeout=5
        )
        attacks.append(("Burst", f"req-{i}", r.status_code))
    except Exception as e:
        attacks.append(("Burst", f"req-{i}", str(e)[:20]))

# 5. Scanner Traps
print("=== Scanner Traps ===")
traps = [
    "/.git/config",
    "/.env",
    "/wp-admin",
    "/phpmyadmin",
    "/adminer",
    "/actuator",
    "/.htaccess",
    "/wp-login.php",
]
for trap in traps:
    try:
        r = requests.get(f"{BASE_URL}/api{trap}", timeout=5)
        attacks.append(("Trap", trap, r.status_code))
    except Exception as e:
        attacks.append(("Trap", trap, str(e)[:20]))

# 6. Directory Traversal
print("=== Path Traversal ===")
paths = [
    "/../../../../etc/passwd",
    "/..\\..\\..\\windows\\system32\\config\\sam",
    "/....//....//....//etc/passwd",
]
for p in paths:
    try:
        r = requests.get(f"{BASE_URL}/api{p}", timeout=5)
        attacks.append(("Traversal", p[:30], r.status_code))
    except Exception as e:
        attacks.append(("Traversal", p[:30], str(e)[:20]))

# 7. Command Injection
print("=== Command Injection ===")
cmds = ["; ls", "| cat /etc/passwd", "`whoami`", "$(id)"]
for cmd in cmds:
    try:
        r = requests.get(f"{BASE_URL}/api/debug{cmd}", timeout=5)
        attacks.append(("Cmd", cmd[:15], r.status_code))
    except Exception as e:
        attacks.append(("Cmd", cmd[:15], str(e)[:20]))

# Save attacks to database
print("\n=== Saving to Database ===")
created = 0
for name, detail, code in attacks:
    try:
        AttackerSession.objects.create(
            ip_address=f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
            user_agent=f"AttackTool/{name}",
            path=f"/api/{detail}",
            method="POST" if "login" in str(detail) else "GET",
            request_score=random.randint(30, 100),
        )
        created += 1
    except Exception as e:
        print(f"Error: {e}")

print(f"Generated {len(attacks)} attacks, {created} saved to database")
