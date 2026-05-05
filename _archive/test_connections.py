import psycopg2
import redis
import os

def test_postgres():
    print("Testing PostgreSQL connection on localhost:5432...")
    try:
        conn = psycopg2.connect(
            host="localhost",
            port=5432,
            user="honeypot",
            password="honeypot-pass-123",
            dbname="honeypot",
            connect_timeout=5
        )
        print("SUCCESS: Connected to PostgreSQL!")
        cur = conn.cursor()
        cur.execute("SELECT version();")
        print(f"PostgreSQL Version: {cur.fetchone()[0]}")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"FAILED: Could not connect to PostgreSQL: {e}")

def test_redis():
    print("\nTesting Redis connection on localhost:6379...")
    try:
        r = redis.Redis(
            host='localhost',
            port=6379,
            password='redis-pass-123',
            socket_connect_timeout=5
        )
        if r.ping():
            print("SUCCESS: Connected to Redis!")
            print(f"Redis Info (version): {r.info()['redis_version']}")
        else:
            print("FAILED: Redis ping failed.")
    except Exception as e:
        print(f"FAILED: Could not connect to Redis: {e}")

if __name__ == "__main__":
    test_postgres()
    test_redis()
