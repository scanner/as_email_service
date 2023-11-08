#!/bin/bash
#
set -o errexit
set -o pipefail
set -o nounset

wait-for-it --service redis:6379 -- echo "Redis available"

echo "Running django migrations.."
/venv/bin/python /app/manage.py migrate

echo "Starting uvicorn.."
/venv/bin/gunicorn config.asgi --bind 127.0.0.1:8000 --chdir=/app -w 4 -k config.uvicorn_worker.UvicornWorker
