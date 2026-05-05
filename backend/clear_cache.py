import os
import django
import hashlib
from django.core.cache import cache

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeypot.settings')
os.environ['REDIS_HOST'] = 'localhost'
django.setup()

def check_cache():
    # Fingerprint for my curl request (assuming default headers)
    # Actually, the user's browser might have a different FP.
    # Let's just list all routes in cache.
    print("Listing all pinned routes in cache:")
    # This is tricky with LocMemCache or Redis depending on config.
    # If it's Redis, we can't easily keys() through Django cache.
    
    # Let's try the common ones.
    ip = '127.0.0.1'
    # My curl user agent was "curl/x.x.x" or similar.
    # Actually, I'll just clear the cache for testing.
    print("Clearing cache to reset any 'Pinned' deception states...")
    cache.clear()
    print("Cache cleared.")

if __name__ == "__main__":
    check_cache()
