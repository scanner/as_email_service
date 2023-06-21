
# -*- Mode: Makefile -*-
ROOT_DIR := $(shell git rev-parse --show-toplevel)
include $(ROOT_DIR)/Make.rules

DOCKER_BUILDKIT := 1

.PHONY: clean lint test mypy logs migrate makemigrations manage_shell shell restart delete stop start build

build: requirements/production.txt requirements/development.txt
	@docker compose build

dbs:
	@mkdir ./dbs

up: build dbs
	@docker compose up --remove-orphans --detach

down:
	@docker compose down --remove-orphans

delete: clean
	@docker compose down --remove-orphans
	@docker volume prune --force

restart:
	@docker compose restart

shell:
	@docker compose run --rm web /bin/bash

manage_shell:
	@docker compose run --rm web python /app/manage.py shell_plus

migrate:
	@docker compose run --rm web python /app/manage.py migrate

makemigrations:
	@docker compose run --rm web python /app/manage.py makemigrations

logs:
	@docker compose logs -f -t

test:
	@docker compose run --rm web pytest --disable-warnings -vvvv
