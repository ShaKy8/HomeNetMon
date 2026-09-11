#!/bin/bash
# Run HomeNetMon in the foreground with production settings (systemd is preferred; see systemd/).
set -euo pipefail
cd "$(dirname "$0")"

# Load .env without word-splitting values (the old `export $(cat .env | xargs)` mangled
# passwords containing spaces or shell metacharacters).
if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    . ./.env
    set +a
fi

export ENV="${ENV:-production}"
export HOST="${HOST:-0.0.0.0}"
export PORT="${PORT:-5000}"
# Keep the database out of the checkout unless the operator chose otherwise.
export DATABASE_URL="${DATABASE_URL:-sqlite:///$(pwd)/production_data/homeNetMon.db}"
mkdir -p production_data

exec venv/bin/gunicorn --workers 1 --worker-class gthread --threads 32 --bind "${HOST}:${PORT}" \
    --timeout 120 --graceful-timeout 30 --access-logfile - --error-logfile - wsgi:app
