#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

wait-for-it --service redis:6379 -- echo "Redis available"
wait-for-it --service spamassassin:783 -- echo "SpamAssassin available"

# Set LISTEN_HOST to `0.0.0.0` if not already set.
#
: "${SMTPD_LISTEN_HOST:=0.0.0.0}"
: "${SMTPD_PORT:=587}"
: "${SMTPD_CERT:=/mnt/ssl/ssl_crt.pem}"
: "${SMTPD_KEY:=/mnt/ssl/ssl_key.pem}"

echo "Starting SMTP daemon"
/venv/bin/python /app/manage.py aiosmtpd \
                 --listen_port="${SMTPD_PORT}" \
                 --listen_host="${SMTPD_LISTEN_HOST}" \
                 --ssl_key="${SMTPD_KEY}" \
                 --ssl_cert="${SMTPD_CERT}"
