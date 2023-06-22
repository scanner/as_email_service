#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

/venv/bin/python /app/manage.py migrate
/venv/bin/python /app/manage.py aiosmtpd \
                 --ssl_key=/mnt/ssl/ssl_key.pem \
                 --ssl_cert=/mnt/ssl/ssl_crt.pem
