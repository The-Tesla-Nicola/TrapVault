import os
from pathlib import Path
from datetime import timedelta
import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get(
    "SECRET_KEY", "change-this-to-a-random-string-of-at-least-50-characters"
)
DEBUG = os.environ.get("DEBUG", "False").lower() == "true"

ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "*").split(",")

# =============================================================================
# INSTALLED APPS
# =============================================================================
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_celery_beat",
    # Third party
    "rest_framework",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    "corsheaders",
    "channels",
    # Local
    "core",
]

AUTH_USER_MODEL = "core.MonitorUser"

# =============================================================================
# MIDDLEWARE
# =============================================================================
MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "core.middleware.AttackDetectionMiddleware",
    "core.middleware.SessionTrackingMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "honeypot.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "core" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "honeypot.wsgi.application"
ASGI_APPLICATION = "honeypot.asgi.application"

# =============================================================================
# DATABASE
# =============================================================================
if os.environ.get("DATABASE_URL"):
    DATABASES = {
        "default": dj_database_url.config(
            default=os.environ.get("DATABASE_URL"),
            conn_max_age=600,
        )
    }
elif os.environ.get("POSTGRES_HOST"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.environ.get("POSTGRES_DB", "honeypot"),
            "USER": os.environ.get("POSTGRES_USER", "honeypot"),
            "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "honeypot123"),
            "HOST": os.environ.get("POSTGRES_HOST", "postgres"),
            "PORT": os.environ.get("POSTGRES_PORT", "5432"),
            "CONN_MAX_AGE": 600,
            "CONN_HEALTH_CHECK": True,
            "OPTIONS": {
                "connect_timeout": 10,
            },
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

# =============================================================================
# CHANNELS (WebSocket support)
# =============================================================================
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [(os.environ.get("REDIS_HOST", "redis"), 6379)],
        },
    },
}

# =============================================================================
# CACHE
# =============================================================================
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": "redis://:{}@{}:6379/1".format(
            os.environ.get("REDIS_PASSWORD", "redispass"),
            os.environ.get("REDIS_HOST", "redis"),
        ),
    }
}

# =============================================================================
# REST FRAMEWORK
# =============================================================================
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.AllowAny",
    ],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "1000/hour",
    },
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
}

# =============================================================================
# JWT SETTINGS
# =============================================================================
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": os.environ.get("JWT_SECRET_KEY", SECRET_KEY),
    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "TOKEN_TYPE_CLAIM": "token_type",
}

# =============================================================================
# CORS - Django is the SINGLE source of truth
# =============================================================================
# In production, set specific allowed origins via ALLOWED_ORIGINS env var
_ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "").split(",")
_ALLOWED_ORIGINS = [u.strip() for u in _ALLOWED_ORIGINS if u.strip()]

if _ALLOWED_ORIGINS:
    CORS_ALLOWED_ORIGINS = _ALLOWED_ORIGINS
    CORS_ALLOW_ALL_ORIGINS = False
else:
    # Development mode only - allow all origins
    CORS_ALLOW_ALL_ORIGINS = DEBUG

CORS_ALLOW_CREDENTIALS = True

# We use JWTs, so CSRF is mostly managed via @csrf_exempt where needed.
CSRF_TRUSTED_ORIGINS = _ALLOWED_ORIGINS

# =============================================================================
# SECURITY (enforced in production)
# =============================================================================
# Cookie security: secure flag enforced in production (when DEBUG=False)
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Production security settings (always enforced regardless of DEBUG)
# SECURE_SSL_REDIRECT = True  # Enable in production with valid SSL cert
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_HSTS_SECONDS = 0  # Enable in production with valid SSL cert
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False

# Additional security settings
SECURE_CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "unique-snowflake",
    }
}
# =============================================================================
# HONEYPOT CONFIGURATION
# =============================================================================
HONEYPOT_CONFIG = {
    # Monitor JWT
    "MONITOR_JWT_SECRET": os.environ.get(
        "MONITOR_JWT_SECRET", "monitor-jwt-secret-change-this-in-production"
    ),
    "MONITOR_ACCESS_TOKEN_LIFETIME": timedelta(hours=4),
    "MONITOR_REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    # Real bank JWT (issued to legitimate customers)
    "REAL_BANK_JWT_SECRET": os.environ.get(
        "REAL_BANK_JWT_SECRET", "real-bank-jwt-secret-change-this-in-production"
    ),
    # Deception response tuning
    "DELAY_MIN_MS": 100,
    "DELAY_MAX_MS": 3000,
    "FAKE_ERROR_RATE": 0.15,
    "BREADCRUMB_RATE": 0.30,
    # Threat scoring weights (additive per event)
    "THREAT_WEIGHTS": {
        "sql_injection": 30,
        "xss": 25,
        "command_injection": 40,
        "path_traversal": 35,
        "ssrf": 35,
        "xxe": 35,
        "auth_bypass": 20,
        "brute_force": 15,
        "data_exfil": 30,
        "reconnaissance": 10,
        "api_probe": 5,
        "login_attempt": 5,
        "other": 2,
    },
    # Auto-block when session threat score exceeds this
    "AUTO_BLOCK_THRESHOLD": 1000,
    # Rate limit per IP per minute
    "RATE_LIMIT_REQUESTS": 500,
    # GeoIP database path (optional)
    "GEOIP_PATH": os.environ.get("GEOIP_PATH", "/app/geoip/GeoLite2-City.mmdb"),
    # Legitimate test users bypass (set via env var, comma-separated)
    "LEGITIMATE_BYPASS_USERS": [
        u.strip().lower()
        for u in os.environ.get(
            "LEGITIMATE_BYPASS_USERS",
            "michael.scott,dwight.schrute"
        ).split(",")
        if u.strip()
    ],
}

SIEM_DECEIVE_THRESHOLD = int(os.environ.get("SIEM_DECEIVE_THRESHOLD", 45))
SIEM_BLOCK_THRESHOLD = int(os.environ.get("SIEM_BLOCK_THRESHOLD", 120))
SIEM_BURST_LIMIT = int(os.environ.get("SIEM_BURST_LIMIT", 20))
SIEM_BRUTE_LIMIT = int(os.environ.get("SIEM_BRUTE_LIMIT", 8))

ALERT_CONFIG = {
    "SLACK_WEBHOOK_URL": os.environ.get("SLACK_WEBHOOK_URL", ""),
    "SMTP_HOST": os.environ.get("SMTP_HOST", ""),
    "SMTP_PORT": os.environ.get("SMTP_PORT", "587"),
    "SMTP_USER": os.environ.get("SMTP_USER", ""),
    "SMTP_PASSWORD": os.environ.get("SMTP_PASSWORD", ""),
    "ALERT_EMAIL_FROM": os.environ.get("ALERT_EMAIL_FROM", "siem@honeypot.local"),
    "ALERT_EMAIL_TO": os.environ.get("ALERT_EMAIL_TO", ""),
}

# =============================================================================
# STATIC FILES
# =============================================================================
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 8},
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# =============================================================================
# LOGGING
# =============================================================================
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {process:d} {thread:d} {message}",
            "style": "{",
        },
        "simple": {
            "format": "{levelname} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        "honeypot": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
        "django": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
    },
}
