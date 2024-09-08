#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

wait-for-it --service redis:6379 -- echo "Redis available"

# Set LISTEN_HOST to `0.0.0.0` if not already set.
#
: "${OUTBOUND_SMTPD_LISTEN_HOST:=0.0.0.0}"
: "${OUTBOUND_SMTPD_PORT:=19246}"
: "${OUTBOUND_SMTPD_CERT:=/mnt/ssl/ssl_crt.pem}"
: "${OUTBOUND_SMTPD_KEY:=/mnt/ssl/ssl_key.pem}"

echo "Starting SMTP daemon"
/venv/bin/python /app/manage.py aiosmtpd \
                 --listen_port="${OUTBOUND_SMTPD_PORT}" \
                 --listen_host="${OUTBOUND_SMTPD_LISTEN_HOST}" \
                 --ssl_key=/mnt/ssl/"${OUTBOUND_SMTPD_KEY}" \
                 --ssl_cert="${OUTBOUND_SMTPD_CERT}"
