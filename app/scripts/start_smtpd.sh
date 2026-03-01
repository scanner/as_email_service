#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

wait-for-it --service redis:6379 -- echo "Redis available"
wait-for-it --service spamassassin:783 -- echo "SpamAssassin available"

: "${SMTPD_LISTEN_HOST:=0.0.0.0}"
: "${SMTPD_SUBMISSION_PORT:=587}"
: "${SMTPD_SMTP_PORT:=off}"

# Default SMTPD_CERT and SMTPD_KEY from HOST_SSL_DIR when it is set and the
# cert/key exist there; allow override via the env vars directly.
#
if [ -n "${HOST_SSL_DIR:-}" ]; then
    : "${SMTPD_CERT:=${HOST_SSL_DIR}/ssl_cert.pem}"
    : "${SMTPD_KEY:=${HOST_SSL_DIR}/ssl_key.pem}"
else
    : "${SMTPD_CERT:=}"
    : "${SMTPD_KEY:=}"
fi

echo "Starting SMTP daemon (submission port: ${SMTPD_SUBMISSION_PORT}, SMTP port: ${SMTPD_SMTP_PORT})"
exec /venv/bin/python /app/manage.py aiosmtpd \
                 --submission_port="${SMTPD_SUBMISSION_PORT}" \
                 --smtp_port="${SMTPD_SMTP_PORT}" \
                 --listen_host="${SMTPD_LISTEN_HOST}" \
                 --ssl_key="${SMTPD_KEY}" \
                 --ssl_cert="${SMTPD_CERT}"
