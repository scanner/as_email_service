# -*- Mode: Makefile -*-
ROOT_DIR := $(shell git rev-parse --show-toplevel)
include $(ROOT_DIR)/Make.rules

DOCKER_BUILDKIT := 1
LATEST_TAG := $(shell git describe --abbrev=0)

.PHONY: clean lint test mypy logs migrate makemigrations createadmin manage_shell shell restart delete down up build dirs help

build: requirements/production.txt requirements/development.txt	## `docker compose build` for both `prod` and `dev` profiles
	@COMPOSE_DOCKER_CLI_BUILD=1 DOCKER_BUILDKIT=1 docker compose --profile prod build
	@COMPOSE_DOCKER_CLI_BUILD=1 DOCKER_BUILDKIT=1 docker compose --profile dev build

dirs: dbs ssl spool	## Make the local directories for dbs, ssl, and spool.

dbs:
	@mkdir $(ROOT_DIR)/dbs

ssl:
	@mkdir $(ROOT_DIR)/ssl

spool:
	@mkdir $(ROOT_DIR)/spool

# XXX Should we have an option to NOT use certs/mkcert (either just make
#     self-signed ourself) in case a developer does not want to go through the
#     potential risks associated with mkcert?
#
ssl/ssl_key.pem ssl/ssl_crt.pem:
	@mkcert -key-file $(ROOT_DIR)/ssl/ssl_key.pem \
                -cert-file $(ROOT_DIR)/ssl/ssl_crt.pem \
                `hostname` localhost 127.0.0.1 ::1

certs: ssl ssl/ssl_key.pem ssl/ssl_crt.pem	## uses `mkcert` to create certificates for local development.

up: build dirs certs	## build and then `docker compose up` for the `dev` profile. Use this to rebuild restart services that have changed.
	@docker compose --profile dev up --remove-orphans --detach

down:	## `docker compose down` for the `dev` profile
	@docker compose --profile dev down --remove-orphans

delete: clean	## docker compose down for `dev` and `prod` and `make clean`.
	@docker compose --profile dev down --remove-orphans
	@docker compose --profile prod down --remove-orphans

restart:	## docker compose restart for the `dev` profile
	@docker compose --profile dev restart

shell:	## Make a bash shell a devweb container
	@docker compose run --rm devweb /bin/bash

manage_shell:	## Run `manage.py shell_plus` in a devweb container.
	@docker compose run --rm devweb python /app/manage.py shell_plus

migrate:	## Run `manage.py migrate` to run all necessary migrations
	@docker compose run --rm devweb python /app/manage.py migrate

makemigrations: build	## Run `manage.py makemigrations` for the as_email app
	@docker compose run --rm devweb python /app/manage.py makemigrations as_email

createadmin: migrate   ## Create django admin account `admin` with password `testpass1234`
	@docker compose run -e DJANGO_SUPERUSER_EMAIL=admin@example.com \
                            -e DJANGO_SUPERUSER_PASSWORD=testpass1234 \
                            --rm devweb \
                            python /app/manage.py createsuperuser --username admin --no-input

logs:	## Tail the logs for devweb, worker, devsmtpd, mailhog
	@docker compose logs -f worker devweb devsmtpd mailhog

test:	## Run all of the tests inside a `devweb` docker container.
	@docker compose run --rm devweb pytest --disable-warnings

release: build	## Make a release. Builds and then tags the latest docker image with most recent git tag. Then pushes it to ghcr.io/scanner/as_email_service_app
	docker tag as_email_service_app:latest as_email_service_app:$(LATEST_TAG)
	docker tag as_email_service_app:latest ghcr.io/scanner/as_email_service_app:$(LATEST_TAG)
	docker push ghcr.io/scanner/as_email_service_app:$(LATEST_TAG)

help:	## Show this help.
	@grep -hE '^[A-Za-z0-9_ \-]*?:.*##.*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
