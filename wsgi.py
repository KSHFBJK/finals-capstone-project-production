# ============================================================
# wsgi.py — Entry point for PhisGuard unified Flask app
# ============================================================

from app import APP  # Import your Flask instance
import sys

# Expose the app to WSGI servers (Gunicorn, uWSGI, etc.)
application = APP

# Optional: local test run
if __name__ == "__main__":
    try:
        from waitress import serve
        HOST = "127.0.0.1"  # Bind to localhost for local testing
        PORT = 8080
        print(f"🚀 PhisGuard running locally at http://{HOST}:{PORT}")
        print("Press Ctrl+C to stop the server")
        serve(application, host=HOST, port=PORT)
    except Exception as e:
        print("❌ Failed to start server:", e, file=sys.stderr)
        sys.exit(1)
