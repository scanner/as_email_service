#!/bin/bash
#
set -o errexit
set -o pipefail
set -o nounset

wait-for-it --service redis:6379 -- echo "Redis available"

/venv/bin/python /app/manage.py compress

echo "Running django migrations.."
/venv/bin/python /app/manage.py migrate

# If HOST_SSL_DIR is set and the cert/key exist there, start gunicorn with
# TLS; otherwise start without.
#
if [ -n "${HOST_SSL_DIR:-}" ]; then
    _CERT="${HOST_SSL_DIR}/ssl_cert.pem"
    _KEY="${HOST_SSL_DIR}/ssl_key.pem"
    if [ -f "${_CERT}" ] && [ -f "${_KEY}" ]; then
        echo "Starting uvicorn with TLS.."
        exec /venv/bin/gunicorn config.asgi \
            --bind 0.0.0.0:8000 --chdir=/app -w 4 \
            -k config.uvicorn_worker.UvicornWorker \
            --certfile "${_CERT}" --keyfile "${_KEY}"
    fi
fi

echo "Starting uvicorn.."
exec /venv/bin/gunicorn config.asgi \
    --bind 0.0.0.0:8000 --chdir=/app -w 4 \
    -k config.uvicorn_worker.UvicornWorker
