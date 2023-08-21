# -*- Mode: Makefile -*-
ROOT_DIR := $(shell git rev-parse --show-toplevel)
include $(ROOT_DIR)/Make.rules

DOCKER_BUILDKIT := 1
LATEST_TAG := $(shell git describe --abbrev=0)

.PHONY: clean lint test mypy logs migrate makemigrations createadmin manage_shell shell restart delete down up build dirs

build: requirements/production.txt requirements/development.txt
	@COMPOSE_DOCKER_CLI_BUILD=1 DOCKER_BUILDKIT=1 docker compose --profile prod build
	@COMPOSE_DOCKER_CLI_BUILD=1 DOCKER_BUILDKIT=1 docker compose --profile dev build

dirs: dbs ssl spool

dbs:
	@mkdir ./dbs

ssl:
	@mkdir ./ssl

spool:
	@mkdir ./spool

up: build dirs
	@docker compose --profile dev up --remove-orphans --detach

down:
	@docker compose --profile dev down --remove-orphans

delete: clean
	@docker compose --profile dev down --remove-orphans
	@docker compose --profile prod down --remove-orphans

restart:
	@docker compose --profile dev restart

shell:
	@docker compose run --rm devweb /bin/bash

manage_shell:
	@docker compose run --rm devweb python /app/manage.py shell_plus

migrate:
	@docker compose run --rm devweb python /app/manage.py migrate

makemigrations: build
	@docker compose run --rm devweb python /app/manage.py makemigrations as_email

createadmin: migrate
	@docker compose run -e DJANGO_SUPERUSER_EMAIL=admin@example.com \
                            -e DJANGO_SUPERUSER_PASSWORD=testpass1234 \
                            --rm devweb \
                            python /app/manage.py createsuperuser --username admin --no-input

logs:
	@docker compose logs -f -t

test:
	@docker compose run --rm devweb pytest --disable-warnings

release: build
	docker tag as_email_service_app:latest as_email_service_app:$(LATEST_TAG)
	docker tag as_email_service_app:latest ghcr.io/scanner/as_email_service_app:$(LATEST_TAG)
	docker push ghcr.io/scanner/as_email_service_app:$(LATEST_TAG)
