#########################
#
# Builder stage
#
FROM python:3.11 as builder

ARG APP_HOME=/app
WORKDIR ${APP_HOME}
COPY requirements/ /app/requirements/
COPY pyproject.toml /app/
RUN python -m venv --copies ${APP_HOME}/venv
RUN . ${APP_HOME}/venv/bin/activate && pip install -r /app/requirements/production.txt

#########################
#
# includes the 'development' requirements
#
FROM builder as builder-dev

ARG APP_HOME=/app
WORKDIR ${APP_HOME}
RUN . ${APP_HOME}/venv/bin/activate && pip install -r requirements/development.txt

#########################
#
# `app` - The docker image for the django app web service
#
FROM python:3.11-slim as app

ARG APP_HOME=/app

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

# We only want the venv we created in the builder. Do not need the
# rest of the cruft.
#
COPY --from=builder /app/venv /app/venv
COPY --from=builder /app/pyproject.toml /app/pyproject.toml

# Puts the venv's python (and other executables) at the front of the
# PATH so invoking 'python' will activate the venv.
#
ENV PATH /app/venv/bin:$PATH

WORKDIR ${APP_HOME}
COPY ./app ./

RUN addgroup --system app \
    && adduser --system --ingroup app app

USER app

CMD ["/app/scripts/start_app.sh"]

#########################
#
# `worker` - The docker image for the huey worker
#
FROM app as worker

CMD ["/app/scripts/start_worker.sh"]

#########################
#
# `smtpd` - The docker image for the smtp daemon
#
FROM app as smtpd

CMD ["/app/scripts/start_smtpd.sh"]
