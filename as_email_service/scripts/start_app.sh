#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

/usr/local/bin/gunicorn config.asgi --bind 0.0.0.0:8000 --chdir=/app -k uvicorn.workers.UvicornWorker
