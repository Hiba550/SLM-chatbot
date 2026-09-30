"""Environment-backed settings with safe local defaults and production checks."""

import os
from urllib.parse import urlsplit
from dotenv import load_dotenv


# Environment variables supplied by the host always take precedence over .env.
load_dotenv(override=False)

APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
IS_PRODUCTION = APP_ENV in {"production", "prod"}

# ── Database ────────────────────────────────────────────────────────────────
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "" if IS_PRODUCTION else "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "" if IS_PRODUCTION else "root")
DB_NAME = os.getenv("DB_NAME", "chatbot_db")
DB_QUERY_TIMEOUT_MS = int(os.getenv("DB_QUERY_TIMEOUT_MS", "15000"))
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "5"))
APP_THREADS = int(os.getenv("APP_THREADS", "4"))
TRUST_PROXY_HOPS = int(os.getenv("TRUST_PROXY_HOPS", "0"))

if not 1000 <= DB_QUERY_TIMEOUT_MS <= 120000:
    raise ValueError("DB_QUERY_TIMEOUT_MS must be between 1000 and 120000 milliseconds.")
if not 2 <= DB_POOL_SIZE <= 32 or not 2 <= APP_THREADS <= 16:
    raise ValueError("DB_POOL_SIZE must be 2-32 and APP_THREADS must be 2-16.")
if not 0 <= TRUST_PROXY_HOPS <= 3:
    raise ValueError("TRUST_PROXY_HOPS must be between 0 and 3.")

# ── Ollama / Model ──────────────────────────────────────────────────────────
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma4:31b-cloud")
MODEL_TIMEOUT_SECONDS = int(os.getenv("MODEL_TIMEOUT_SECONDS", "90"))
MODEL_MAX_CONCURRENT = int(os.getenv("MODEL_MAX_CONCURRENT", "1"))
MODEL_QUEUE_WAIT_SECONDS = float(os.getenv("MODEL_QUEUE_WAIT_SECONDS", "3"))
if not 15 <= MODEL_TIMEOUT_SECONDS <= 180 or not 1 <= MODEL_MAX_CONCURRENT <= 4 or not 0 <= MODEL_QUEUE_WAIT_SECONDS <= 10:
    raise ValueError("Model timeout, concurrency, or queue wait is outside the supported range.")

# ── Security ────────────────────────────────────────────────────────────────
SESSION_TTL_MINS = int(os.getenv("SESSION_TTL_MINS", os.getenv("JWT_EXPIRY_MINS", "480")))
if not 5 <= SESSION_TTL_MINS <= 1440:
    raise ValueError("SESSION_TTL_MINS must be between 5 minutes and 24 hours.")


SESSION_SECRET = os.getenv("SESSION_SECRET", os.getenv("JWT_SECRET", "")).strip()
if IS_PRODUCTION:
    if len(SESSION_SECRET) < 32:
        raise RuntimeError("Production requires a SESSION_SECRET with at least 32 characters.")
    if not DB_USER or DB_USER.lower() == "root" or not DB_PASSWORD:
        raise RuntimeError("Production requires a dedicated non-root database user and password.")
else:
    # Preserves existing sample-workspace sessions; production refuses this fallback.
    SESSION_SECRET = SESSION_SECRET or "chatbot_jwt_secret_key_change_in_prod"

# ── App ─────────────────────────────────────────────────────────────────────
PORT = int(os.getenv("PORT", "5000"))
HOST = os.getenv("HOST", "127.0.0.1")
APP_ORIGIN = os.getenv("APP_ORIGIN", "").strip().rstrip("/")
if IS_PRODUCTION:
    origin_parts = urlsplit(APP_ORIGIN)
    if (
        origin_parts.scheme != "https"
        or not origin_parts.netloc
        or not origin_parts.hostname
        or any(character.isspace() for character in APP_ORIGIN)
        or origin_parts.username
        or origin_parts.password
        or origin_parts.path
        or origin_parts.query
        or origin_parts.fragment
    ):
        raise RuntimeError("Production requires APP_ORIGIN set to its HTTPS public origin.")
DEBUG = os.getenv("FLASK_DEBUG", "false").strip().lower() in {"1", "true", "yes"}
if IS_PRODUCTION:
    DEBUG = False
