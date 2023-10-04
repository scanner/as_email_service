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

#########################
#
# includes the 'development' requirements
#
FROM builder as dev

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

ARG APP_HOME=/app
WORKDIR ${APP_HOME}

COPY requirements/development.txt /app/requirements/development.txt
RUN . /venv/bin/activate && pip install -r requirements/development.txt

# Puts the venv's python (and other executables) at the front of the
# PATH so invoking 'python' will activate the venv.
#
ENV PATH /venv/bin:$PATH

WORKDIR ${APP_HOME}
COPY ./app ./

RUN /venv/bin/python \
    /app/manage.py collectstatic --clear --no-input --verbosity 0

RUN addgroup --system app \
    && adduser --system --ingroup app app

USER app

CMD ["/app/scripts/start_app.sh"]

#########################
#
# `app` - The docker image for the django app web service
#
FROM python:3.11-slim as prod

ARG APP_HOME=/app

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

# We only want the venv we created in the builder. Do not need the
# rest of the cruft.
#
COPY --from=builder /venv /venv
COPY --from=builder /app/pyproject.toml /app/pyproject.toml

# Puts the venv's python (and other executables) at the front of the
# PATH so invoking 'python' will activate the venv.
#
ENV PATH /venv/bin:$PATH

WORKDIR ${APP_HOME}
COPY ./app ./

RUN /venv/bin/python \
    /app/manage.py collectstatic --clear --no-input --verbosity 0
RUN  /venv/bin/python /app/manage.py compile_pyc

RUN addgroup --system app \
    && adduser --system --ingroup app app

USER app
CMD ["/app/scripts/start_app.sh"]
