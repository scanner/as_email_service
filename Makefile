# -*- Mode: Makefile -*-
ROOT_DIR := $(shell git rev-parse --show-toplevel)
include $(ROOT_DIR)/Make.rules

DOCKER_BUILDKIT := 1
LATEST_TAG := $(shell git describe --abbrev=0)

.PHONY: clean test logs migrate makemigrations createadmin manage_shell shell restart delete down up build dirs sync lock add add-dev upgrade help api-schema api-docs

build: version	## Build prod and dev Docker images
	@COMPOSE_DOCKER_CLI_BUILD=1 DOCKER_BUILDKIT=1 docker build --build-arg PYTHON_VERSION="$(PYTHON_VERSION)" --build-arg VERSION="$(VERSION)" --build-arg SALT_KEY=build-placeholder --target prod --tag as_email_service:$(VERSION) --tag as_email_service:latest .
	@COMPOSE_DOCKER_CLI_BUILD=1 DOCKER_BUILDKIT=1 docker build --build-arg PYTHON_VERSION="$(PYTHON_VERSION)" --build-arg VERSION="$(VERSION)" --build-arg SALT_KEY=build-placeholder --target dev --tag as_email_service:$(VERSION)-dev --tag as_email_service:dev .

uv-sync: .venv	## Sync .venv with uv.lock (run after updating pyproject.toml or pulling changes)
	@uv sync

uv-lock:	## Update uv.lock file from pyproject.toml dependencies
	@uv lock

uv-add:	## Add a new dependency (usage: make add PACKAGE=requests)
	@if [ -z "$(PACKAGE)" ]; then \
		echo "Error: PACKAGE not specified. Usage: make add PACKAGE=requests"; \
		exit 1; \
	fi
	@uv add $(PACKAGE)

uv-add-dev:	## Add a new dev dependency (usage: make add-dev PACKAGE=pytest-xdist)
	@if [ -z "$(PACKAGE)" ]; then \
		echo "Error: PACKAGE not specified. Usage: make add-dev PACKAGE=pytest-xdist"; \
		exit 1; \
	fi
	@uv add --dev $(PACKAGE)

uv-upgrade:	## Upgrade all dependencies to latest compatible versions
	@uv sync --upgrade

dirs: dbs ssl spool spama    ## Make the local directories for dbs, ssl, and spool.

dbs:
	@mkdir -p $(ROOT_DIR)/dbs

ssl:
	@mkdir -p $(ROOT_DIR)/ssl

spool:
	@mkdir -p $(ROOT_DIR)/spool

spama:
	@mkdir -p $(ROOT_DIR)/spama/logs
	@mkdir -p $(ROOT_DIR)/spama/config
	@mkdir -p $(ROOT_DIR)/spama/data

# XXX Should we have an option to NOT use certs/mkcert (either just make
#     self-signed ourself) in case a developer does not want to go through the
#     potential risks associated with mkcert?
#
ssl/ssl_key.pem ssl/ssl_crt.pem:
	@mkcert -key-file $(ROOT_DIR)/ssl/ssl_key.pem \
                -cert-file $(ROOT_DIR)/ssl/ssl_crt.pem \
                `hostname` localhost 127.0.0.1 ::1

certs: ssl ssl/ssl_key.pem ssl/ssl_crt.pem	## uses `mkcert` to create certificates for local development.

up: build dirs certs	## build and then `docker compose up`
	@docker compose up --remove-orphans --detach

down:	## `docker compose down`
	@docker compose  down

delete: clean	## docker compose down for `dev` and `prod` and `make clean`.
	@docker compose down --remove-orphans

restart:	## docker compose restart
	@docker compose restart

shell:	## Make a bash shell an ephemeral web container
	@docker compose run --rm web /bin/bash

exec_shell: ## Make a bash shell in the docker-compose running web container
	@docker compose exec web /bin/bash

manage_shell:	## Run `manage.py shell_plus` in a web container.
	@docker compose run --rm web /venv/bin/python /app/manage.py shell_plus

migrate:	## Run `manage.py migrate` to run all necessary migrations
	@docker compose run --rm web /venv/bin/python /app/manage.py migrate

makemigrations:	## Run `manage.py makemigrations` for the as_email app
	@PYTHONPATH=$(ROOT_DIR)/app $(UV_RUN) python app/manage.py makemigrations as_email

createadmin: migrate   ## Create django admin account `admin` with password `testpass1234`
	@docker compose run -e DJANGO_SUPERUSER_EMAIL=admin@example.com \
                            -e DJANGO_SUPERUSER_PASSWORD=testpass1234 \
                            --rm web \
                            /venv/bin/python /app/manage.py createsuperuser --username admin --no-input

logs:	## Tail the logs for web, worker, smtpd, mailhog
	@docker compose logs -f worker web smtpd mailhog

test: .venv	## Run all of the tests
	@$(UV_RUN) pytest --cov=as_email --cov-report=html app/
	@echo "HTML coverage report generated in htmlcov/index.html"

release: build	## Make a release. Builds and then tags the latest docker image with most recent git tag. Then pushes it to ghcr.io/scanner/as_email_service
	docker tag as_email_service:latest as_email_service:$(LATEST_TAG)
	docker tag as_email_service:latest ghcr.io/scanner/as_email_service:$(LATEST_TAG)
	docker push ghcr.io/scanner/as_email_service:$(LATEST_TAG)

api-schema: .venv docs	## Generate OpenAPI schema YAML into docs/openapi.yaml
	@$(UV_RUN) python app/manage.py spectacular --color --file docs/openapi.yaml
	@echo "OpenAPI schema written to docs/openapi.yaml"

api-docs: api-schema	## Generate API markdown docs from OpenAPI schema
	@$(UV_RUN) python app/scripts/generate_api_docs.py docs/openapi.yaml docs/api.md
	@echo "API docs written to docs/api.md"

docs:
	@mkdir -p $(ROOT_DIR)/docs

help:	## Show this help.
	@grep -hE '^[A-Za-z0-9_ \-]*?:.*##.*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
