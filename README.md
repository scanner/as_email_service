[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
# Apricot Systematic Email Service (as_email_service)
A Django app and smtp relay service for working with 3rd party email services (well, just [Postmark](https://postmarkapp.com/) initially. Also supports delivery to an MH email box on the same machine (for use with [asimap](https://github.com/scanner/asimap/) hosted on the same machine).

## Table of Contents

- [Setup](#setup)
- [Configuration](#configuration)
- [Administration](#administration)
- [Design](#design)
- [Local Development](#local-development)

## Setup

1. Linux host running docker with at least 2gb of RAM to run all of the services. More if you have a lot of email servers at postmark that this is handling email for.

## Configuration

The `docker-compose.yml` file in this repo has all that is necessary to run the system services. Most configuration for dealing with postmark and users is handled directly within the django-admin. For setting up the service itself you will need a `.env` file with the necessary values filled in.

Here is a minimal set of env. vars you will need to set in the .env for your services:

``` ini
# This project uses a .env file for basic configuration and passing secrets to
# the AS Email Service.
#
# Naturally due to the sensitive nature of this file access to it must be
# carefully controlled.
#
# This is a get-the-thing-off-the-ground setup.
#
# The following env. vars are required for the service to function.
#
DJANGO_SECRET_KEY=<your sites secret key here>
EMAIL_BACKEND=<backend to use>
ANYMAIL="key1=value1,key2=value2"
SITE_NAME=your_email_server.your.domain
DEFAULT_FROM_EMAIL = "you@example.com"
SERVER_EMAIL = "your-server@example.com"

# Key/value pairs for your configured servers at postmark. The key is the name
# of the server, they key is the API key for that server.
#
EMAIL_SERVER_TOKENS="example.com=foo,example.org=baz"

# All of these parts are setup based on the default docker-compose file that
# mounts file values under /mnt/db, /mnt/spool, /mnt/mail_dirs/, /mnt/ssl
#
DATABASE_URL=sqlite:////mnt/db/as_email_service.db
EMAIL_SPOOL_DIR=/mnt/spool
MAIL_DIRS=/mnt/mail_dirs
HOST_SPOOL_ROOT=/mnt/spool
HOST_MAIL_ROOT=/mnt/mail_dirs
HOST_DB_DIR=/mnt/dbs
HOST_SSL_DIR=/mnt/ssl

# What docker tag to pull and run
#
RELEASE_VERSION=latest
```

## Administration

## Design

## Local Development

## Contributing

## License

BSD 3-Clause License
