#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

# XXX EMAIL_SPOOL_DIR is now in django settings..
/venv/bin/python /app/manage.py aiosmtpd \
                 --spool_dir="${EMAIL_SPOOL_DIR}" \
                 --ssl_key=/mnt/ssl/ssl_key.pem \
                 --ssl_cert=/mnt/ssl/ssl_crt.pem
