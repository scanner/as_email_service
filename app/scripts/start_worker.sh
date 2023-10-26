#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

wait-for-it --service redis:6379 -- echo "Redis available"
/venv/bin/python /app/manage.py migrate
/venv/bin/python /app/manage.py run_huey
