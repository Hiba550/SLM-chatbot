"""Bounded threaded WSGI entry point for local and proxied deployments."""

from waitress import serve

from app import app
from config import APP_THREADS, HOST, MODEL_TIMEOUT_SECONDS, PORT


if __name__ == "__main__":
    serve(
        app,
        host=HOST,
        port=PORT,
        threads=APP_THREADS,
        connection_limit=max(20, APP_THREADS * 8),
        channel_timeout=MODEL_TIMEOUT_SECONDS + 30,
        max_request_body_size=16 * 1024,
        max_request_header_size=16 * 1024,
        expose_tracebacks=False,
    )
