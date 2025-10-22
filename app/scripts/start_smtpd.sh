#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

wait-for-it --service redis:6379 -- echo "Redis available"
wait-for-it --service spamassassin:783 -- echo "SpamAssassin available"

: "${SMTPD_LISTEN_HOST:=0.0.0.0}"
: "${SMTPD_SUBMISSION_PORT:=587}"
: "${SMTPD_SMTP_PORT:=25}"
: "${SMTPD_CERT:=/mnt/ssl/ssl_crt.pem}"
: "${SMTPD_KEY:=/mnt/ssl/ssl_key.pem}"

echo "Starting SMTP daemon (submission port: ${SMTPD_SUBMISSION_PORT}, SMTP port: ${SMTPD_SMTP_PORT})"
/venv/bin/python /app/manage.py aiosmtpd \
                 --submission_port="${SMTPD_SUBMISSION_PORT}" \
                 --smtp_port="${SMTPD_SMTP_PORT}" \
                 --listen_host="${SMTPD_LISTEN_HOST}" \
                 --ssl_key="${SMTPD_KEY}" \
                 --ssl_cert="${SMTPD_CERT}"
