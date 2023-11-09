"""
Django settings for as_email_service project.

Generated by 'django-admin startproject' using Django 4.2.1.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""
# System imports
#
from pathlib import Path

import environ
import redis

# 3rd party imports
#
import sentry_sdk
from django.utils.crypto import get_random_string

# This is be "/app" inside the docker container.
#
BASE_DIR = Path(__file__).parent.parent

# NOTE: We provide a default secret key so that we can run 'collectstatic'
#       during the docker image build phase. When actually run this will be
#       via a .env passed to the container.
#
# NOTE: We provide our own set of characters because we need to specifically
#       exclude '$' so that environ does not think it is some proxied value.
#
random_chars = "abcdefghijklmnopqrstuvwxyz0123456789!@#%^&*(-_=+)"
env = environ.FileAwareEnv(
    DEBUG=(bool, False),
    DJANGO_SECRET_KEY=(str, get_random_string(50, random_chars)),
    SITE_NAME=(str, "example.com"),
    DATABASE_URL=(str, "sqlite:///:memory:"),
    EMAIL_SPOOL_DIR=(str, "/mnt/spool"),
    EMAIL_SERVER_TOKENS=(dict, {"example.com": "foo"}),
    MAIL_DIRS=(str, "/mnt/mail_dir"),
    DEFAULT_FROM_EMAIL=(str, "admin@example.com"),
    ALLOWED_HOSTS=(list, list()),
    REDIS_SERVER=(str, "redis"),
    VERSION=(str, "unknown"),
    CACHE_URL=(str, "dummycache://"),
    SENTRY_DSN=(str, None),
    SENTRY_TRACES_SAMPLE_RATE=(float, 0.0),
)

# NOTE: We should try moving secrets to compose secrets.
#
DEBUG = env("DEBUG")
SECRET_KEY = env("DJANGO_SECRET_KEY")
SITE_NAME = env("SITE_NAME")
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS")
if ALLOWED_HOSTS:
    CSRF_TRUSTED_ORIGINS = [f"https://{x}" for x in ALLOWED_HOSTS]
REDIS_SERVER = env("REDIS_SERVER")
VERSION = env("VERSION")

SENTRY_TRACES_SAMPLE_RATE = env("SENTRY_TRACES_SAMPLE_RATE")
SENTRY_DSN = env("SENTRY_DSN")
if SENTRY_DSN is not None:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        # Set traces_sample_rate to 1.0 to capture 100%
        # of transactions for performance monitoring.
        traces_sample_rate=SENTRY_TRACES_SAMPLE_RATE,
        # Set profiles_sample_rate to 1.0 to profile 100%
        # of sampled transactions.
        # We recommend adjusting this value in production.
        profiles_sample_rate=1.0,
        environment="devel" if DEBUG else "production",
        release=f"as_email_service@{VERSION}",
    )

# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "compressor",
    "anymail",
    "django_extensions",
    "huey.contrib.djhuey",
    "ordered_model",
    "rest_framework",
    "dry_rest_permissions",
    "crispy_forms",
    "crispy_bulma",
    "django_simple_bulma",
    "project",  # NOTE: project wide templatetags, etc.
    "as_email",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "django_settings_export.settings_export",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

REST_FRAMEWORK = {
    # All access to the as_email API requires authentication. Additional
    # permissions are defined on each of the models.
    #
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]
}

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {"default": env.db()}


# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",  # noqa: E501
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

LOGIN_REDIRECT_URL = "home"
LOGOUT_REDIRECT_URL = "home"

TIME_ZONE = "America/Los_Angeles"
# https://docs.djangoproject.com/en/dev/ref/settings/#language-code
LANGUAGE_CODE = "en-us"
# https://docs.djangoproject.com/en/dev/ref/settings/#site-id
SITE_ID = 1
# https://docs.djangoproject.com/en/dev/ref/settings/#use-i18n
USE_I18N = True
# https://docs.djangoproject.com/en/dev/ref/settings/#use-tz
USE_TZ = True
# https://docs.djangoproject.com/en/dev/ref/settings/#locale-paths
LOCALE_PATHS = [str(BASE_DIR / "locale")]


# STATIC
# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/
#
# ------------------------------------------------------------------------------
STATIC_ROOT = str(BASE_DIR / "staticfiles")
STATIC_URL = "static/"
STATICFILES_DIRS = [str(BASE_DIR / "static")]
STATICFILES_FINDERS = [
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
    "compressor.finders.CompressorFinder",
    "django_simple_bulma.finders.SimpleBulmaFinder",
]

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
CACHES = {"default": env.cache_url("CACHE_URL")}

HUEY = {
    "huey_class": "huey.RedisHuey",
    "name": "as_email_service",
    "immediate": False,
    "results": True,  # Store return values of tasks.
    "store_none": False,
    "utc": True,  # Use UTC for all times internally.
    "connection": {
        "connection_pool": redis.ConnectionPool(
            host=REDIS_SERVER, port=6379, db=1
        ),
    },
    "consumer": {
        "workers": 8,
        "worker_type": "thread",
        "scheduler_interval": 1,  # Check schedule every second, -s.
        "periodic": True,  # Enable crontab feature.
        "check_worker_health": True,  # Enable worker health checks.
    },
}

DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", default="admin@example.com")
SERVER_EMAIL = env("SERVER_EMAIL", default=DEFAULT_FROM_EMAIL)
EMAIL_SUBJECT_PREFIX = env(
    "DJANGO_EMAIL_SUBJECT_PREFIX",
    default="[AS Email Service]",
)

# If EMAIL_BACKEND is set, configure anymail. Otherwise use `EMAIL_HOST`
if "EMAIL_BACKEND" in env:
    EMAIL_BACKEND = env("EMAIL_BACKEND")
    ANYMAIL = env.dict("ANYMAIL")
else:
    # https://docs.djangoproject.com/en/dev/ref/settings/#email-host
    EMAIL_HOST = env("EMAIL_HOST", default="mailhog")
    # https://docs.djangoproject.com/en/dev/ref/settings/#email-port
    EMAIL_PORT = 1025

# A dict of the tokens for access to the postmark mail 'server's. The
# key is the name of the server at postmark, and the value is the
# server token for that server.
#
EMAIL_SERVER_TOKENS = env.dict("EMAIL_SERVER_TOKENS")

# The email spool dir is where incoming and outgoing emails are temporarily
# stored. There should be a directory for every 'Server' and in that server's
# directory there will be an "incoming" and "outgoing" directory.
#
EMAIL_SPOOL_DIR = Path(env("EMAIL_SPOOL_DIR"))

# This is the parent directory where all the MH mail dirs are for all the
# email accounts. There will be a subdir for each server, and a dir with the
# username under that subdir. That username dir will be the mh mail dir for
# each email account.
#
MAIL_DIRS = Path(env("MAIL_DIRS"))

# The external auth db is a sqlite db that we maintain one table in: "users"
# The "user" table will at least have two columns: "password" and
# "maildir". This is for use by external services (primarily for integration
# with asimap as we do not want to bind asimap to a django project.. but we do
# want this django app to be the authorities for the username, password, and
# maildir root for that account.
#
# Whenever an email account is saved this db is updated. If it does not exist
# it is created.
#
# NOTE: We should probably make an importable module from asimap that manages
#       this db and use that to create, update, and modify this db.
#
EXTERNAL_AUTH_DB = (
    Path(env("EXTERNAL_AUTH_DB")) if "EXTERNAL_AUTH_DB" in env else None
)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "basic": {
            "format": "[{asctime}] {levelname}:{module}.{funcName}: {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "basic",
        },
    },
    "loggers": {
        "as_email": {
            "handlers": ["console"],
            "level": "DEBUG" if DEBUG else "INFO",
            "propagate": True,
        },
        "mail": {
            "handlers": ["console"],
            "level": "DEBUG" if DEBUG else "WARNING",
            "propagate": True,
        },
    },
}

# Django Compressor
#
COMPRESS_OFFLINE = not DEBUG
COMPRESS_FILTERS = {
    "css": [
        "compressor.filters.css_default.CssAbsoluteFilter",
        "compressor.filters.cssmin.rCSSMinFilter",
        "compressor.filters.cssmin.CSSCompressorFilter",
    ],
    "js": ["compressor.filters.jsmin.rJSMinFilter"],
}

# django-simple-bulma
#
BULMA_SETTINGS = {
    "extensions": [
        "bulma-collapsible",
        "bulma-notifications",
        "bulma-modal",
        "bulma-navbar-burger",
        "bulma-tooltip",
        "bulma-divider",
        "bulma-switch",
        "bulma-coolcheckboxes",
        "bulma-ribbon",
    ],
    "output_style": "nested" if DEBUG else "compressed",
}

# What settings do we export to the template system
#
SETTINGS_EXPORT = [
    "DEBUG",
    "VERSION",
]

# django-crispy-forms
#
CRISPY_ALLOWED_TEMPLATE_PACKS = "bulma"
CRISPY_TEMPLATE_PACK = "bulma"
CRISPY_FAIL_SILENTLY = not DEBUG
