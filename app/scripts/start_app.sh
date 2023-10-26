#!/bin/bash
#
set -o errexit
set -o pipefail
set -o nounset

wait-for-it --service redis:6379 -- echo "Redis available"
# XXX We collectstatic in the docker image build step so we should probably
#     remove this.
/venv/bin/python /app/manage.py collectstatic --clear --no-input --verbosity 0
/venv/bin/python /app/manage.py migrate
/venv/bin/gunicorn config.asgi --bind 0.0.0.0:8000 --chdir=/app -w 4 -k uvicorn.workers.UvicornWorker
