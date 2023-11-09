#########################
#
# Builder stage
#
FROM python:3.11 as builder

ARG APP_HOME=/app
WORKDIR ${APP_HOME}
COPY requirements/production.txt /app/requirements/production.txt
COPY pyproject.toml /app/
RUN python -m venv --copies /venv
RUN . /venv/bin/activate && \
    pip install --upgrade pip && \
    pip install --upgrade setuptools && \
    pip install -r /app/requirements/production.txt
ENV PATH /venv/bin:$PATH

#########################
#
# This image is meant for doing the `collectstatic` and `compress` steps along
# with the software (node, npm, esbuild) they need to do their work. The
# results are copied in to the `prod` image instead of running collectstatic as
# part of the `prod` image building.
#
# The key thing here is to not need node, npm, esbuild etc in our `prod` image
# keeping it smaller and free of software not needed for actually serving the
# site.
#
FROM builder as precompiler

ARG APP_HOME=/app
WORKDIR ${APP_HOME}
COPY ./app ./
RUN apt update
RUN apt install --assume-yes npm
RUN npm install esbuild
RUN /venv/bin/python \
    /app/manage.py collectstatic --clear --no-input --verbosity 0
RUN /venv/bin/python /app/manage.py compress --force

#########################
#
# includes the 'development' requirements
#
FROM precompiler as dev

LABEL org.opencontainers.image.source=https://github.com/scanner/as_email_service
LABEL org.opencontainers.image.description="Apricot Systematic Email Service"
LABEL org.opencontainers.image.licenses=BSD-3-Clause

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

ARG APP_HOME=/app
WORKDIR ${APP_HOME}

COPY requirements/development.txt /app/requirements/development.txt
RUN . /venv/bin/activate && pip install -r requirements/development.txt

RUN apt install --assume-yes jove vim && apt clean

# Puts the venv's python (and other executables) at the front of the
# PATH so invoking 'python' will activate the venv.
#
ENV PATH /venv/bin:$PATH

WORKDIR ${APP_HOME}
COPY ./app ./

RUN addgroup --system --gid 900 app \
    && adduser --system --uid 900 --ingroup app app

RUN chown -R app /app

USER app

CMD ["/app/scripts/start_app.sh"]

#########################
#
# `app` - The docker image for the django app web service
#
FROM python:3.11-slim as prod

LABEL org.opencontainers.image.source=https://github.com/scanner/as_email_service
LABEL org.opencontainers.image.description="Apricot Systematic Email Service"
LABEL org.opencontainers.image.licenses=BSD-3-Clause

ARG APP_HOME=/app

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

# We only want the venv we created in the builder. Do not need the
# rest of the cruft.
#
COPY --from=builder /venv /venv
COPY --from=builder /app/pyproject.toml /app/pyproject.toml
COPY --from=precompiler /app/staticfiles /app/staticfiles

# Puts the venv's python (and other executables) at the front of the
# PATH so invoking 'python' will activate the venv.
#
ENV PATH /venv/bin:$PATH

WORKDIR ${APP_HOME}
COPY ./app ./

RUN /venv/bin/python /app/manage.py compile_pyc

RUN addgroup --system --gid 900 app \
    && adduser --system --uid 900 --ingroup app app

USER app
CMD ["/app/scripts/start_app.sh"]
