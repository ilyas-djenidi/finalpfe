# gunicorn.conf.py — CyBrain production server config
# ─────────────────────────────────────────────────────
# SQLite + WAL mode supports concurrent readers but ONLY ONE writer at a time.
# Using a single PROCESS (not multiple workers) eliminates write contention.
# We compensate with threads for I/O concurrency (scans, AI calls, etc.)

import os

# Binding — Render injects PORT, default 5000 for local dev
bind = f"0.0.0.0:{os.environ.get('PORT', '5000')}"

# Single process → no SQLite write conflicts across workers
workers     = 1
worker_class = "gthread"
threads     = 4          # async I/O for concurrent scan + AI requests

# Timeouts — scans can take several minutes
timeout     = 600        # 10 min hard limit per request (long DAST/nmap scans)
keepalive   = 5
graceful_timeout = 30

# Limits
max_requests        = 1000
max_requests_jitter = 100

# Logging — stdout/stderr only (no file I/O; Render captures logs automatically)
accesslog   = "-"        # stdout
errorlog    = "-"        # stderr
loglevel    = "info"
capture_output = True

# Process name shown in Render logs
proc_name   = "cybrain"
