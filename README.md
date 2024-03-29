[![Build
Status](https://drone.apricot.com/api/badges/scanner/as_email_service/status.svg?ref=refs/heads/main)](https://drone.apricot.com/scanner/as_email_service)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)

# Apricot Systematic Email Service (as_email_service)

A Django app and smtp relay service for working with 3rd party email services (well, just [Postmark](https://postmarkapp.com/) initially. Also supports delivery to an MH email box on the same machine (for use with [asimap](https://github.com/scanner/asimap/) hosted on the same machine).

## Table of Contents

- [Setup](#setup)
- [Configuration](#configuration)
- [Administration](#administration)
- [Design](#design)
- [Local Development](#local-development)
- [Contributing](#contributing)
- [License](#license)

## Setup

1. Linux host running docker with at least 2gb of RAM to run all of the services. More if you have a lot of email servers at postmark that this is handling email for.

## Configuration

The `docker-compose.yml` file in this repo has all that is necessary to run the system services. Most configuration for dealing with postmark and users is handled directly within the django-admin. For setting up the service itself you will need a `.env` file with the necessary values filled in.

Here is a minimal set of env. vars you will need to set in the .env for your services:

```ini
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

**NOTE**: This project uses `mkcert` to generate and use SSL certificates for
development. See [https://github.com/FiloSottile/mkcert](https://github.com/FiloSottile/mkcert) for details. The `Makefile` and supporting scripts assume that you have already run `mkcert -install` to setup the local trusted CA for development.

### Required Installed Packages

Even if you are not going to download new python and node modules you need at
least these packages installed for local development:

- python (3.11 or greater)
- npm
- docker

## Contributing

## License

[./LICENSE](BSD 3-Clause License)

### Favicon

This favicon was generated using the following graphics from Twitter Twemoji:

- Graphics Title: 1f4e8.svg
- Graphics Author: Copyright 2020 Twitter, Inc and other contributors (https://github.com/twitter/twemoji)
- Graphics Source: https://github.com/twitter/twemoji/blob/master/assets/svg/1f4e8.svg
- Graphics License: CC-BY 4.0 (https://creativecommons.org/licenses/by/4.0/)
