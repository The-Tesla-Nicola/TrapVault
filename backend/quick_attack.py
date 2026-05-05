import requests

BASE = "http://127.0.0.1:8000"
for pw in ["password", "123456", "admin", "letmein", "qwerty", "12345678"]:
    r = requests.post(
        f"{BASE}/api/auth/login/", json={"username": "admin", "password": pw}
    )
    print(f"Brute: {pw} -> {r.status_code}")
for sql in ["admin' --", "admin' OR '1'='1"]:
    r = requests.post(
        f"{BASE}/api/auth/login/", json={"username": sql, "password": "x"}
    )
    print(f"SQLi -> {r.status_code}")
for u, p in [("test", "test"), ("root", "root")]:
    r = requests.post(f"{BASE}/api/auth/login/", json={"username": u, "password": p})
    print(f"Stuffing: {u}:{p} -> {r.status_code}")
for i in range(25):
    r = requests.get(f"{BASE}/api/telemetry/capture/", json={"t": i})
print(f"Burst: 25 -> {r.status_code}")
for t in ["/.git/config", "/.env", "/wp-admin", "/phpmyadmin", "/actuator"]:
    r = requests.get(f"{BASE}/api{t}")
    print(f"Trap: {t} -> {r.status_code}")
for p in ["/../../etc/passwd"]:
    r = requests.get(f"{BASE}/api{p}")
    print(f"Trav: {p} -> {r.status_code}")
print("Attacks generated!")
