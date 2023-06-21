#!/bin/bash
#
set -o errexit
set -o pipefail
set -o nounset

/venv/bin/python /app/manage.py migrate
/venv/bin/gunicorn as_email_service.asgi --bind 0.0.0.0:8000 --chdir=/app -w 4 -k uvicorn.workers.UvicornWorker
