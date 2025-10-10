#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

wait-for-it --service redis:6379 -- echo "Redis available"

# Set LISTEN_HOST to `0.0.0.0` if not already set.
#
: "${LOCAL_SMTPD_LISTEN_HOST:=0.0.0.0}"
: "${LOCAL_SMTPD_PORT:=19247}"
: "${LOCAL_SMTPD_CERT:=/mnt/ssl/incoming_mail_crt.pem}"
: "${LOCAL_SMTPD_KEY:=/mnt/ssl/incoming_mail_key.pem}"

echo "Starting SMTP daemon"
/venv/bin/python /app/manage.py aiosmtpd \
                 --listen_port="${LOCAL_SMTPD_PORT}" \
                 --listen_host="${LOCAL_SMTPD_LISTEN_HOST}" \
                 --ssl_key=/mnt/ssl/"${LOCAL_SMTPD_KEY}" \
                 --ssl_cert="${LOCAL_SMTPD_CERT}"
