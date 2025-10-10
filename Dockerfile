#########################
#
# Builder stage - Use slim image with build tools
# This stage installs build dependencies temporarily to compile Python packages
#
FROM python:3.12-slim as builder

ARG APP_HOME=/app
WORKDIR ${APP_HOME}

# Install build dependencies needed to compile Python packages with C extensions
# These will NOT be in the final image
#
RUN apt-get update && \
    apt-get install --assume-yes --no-install-recommends \
    gcc \
    g++ \
    make \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements/production.txt /app/requirements/production.txt
COPY pyproject.toml /app/

# Create venv and install production dependencies
#
RUN python -m venv --copies /venv && \
    . /venv/bin/activate && \
    pip install --no-cache-dir --upgrade pip setuptools && \
    pip install --no-cache-dir -r /app/requirements/production.txt

# Clean up unnecessary files from venv to reduce size
#
RUN find /venv -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true && \
    find /venv -type d -name 'tests' -prune -exec rm -rf {} + 2>/dev/null || true && \
    find /venv -type d -name 'test' -prune -exec rm -rf {} + 2>/dev/null || true

#########################
#
# Development stage - includes development requirements and debugging tools
# This is a larger image with all the tools you need for development
#
FROM python:3.12-slim as dev

LABEL org.opencontainers.image.source=https://github.com/scanner/as_email_service
LABEL org.opencontainers.image.description="Apricot Systematic Email Service (Development)"
LABEL org.opencontainers.image.licenses=BSD-3-Clause

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

ARG APP_HOME=/app
WORKDIR ${APP_HOME}

# Install runtime dependencies + build tools + development tools
RUN apt-get update && \
    apt-get install --assume-yes --no-install-recommends \
    # Runtime libraries (same as prod)
    libpq5 \
    # Build tools (needed for installing dev dependencies)
    gcc \
    g++ \
    make \
    libpq-dev \
    # Development and debugging tools
    jove \
    vim \
    git \
    curl \
    procps \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the production venv from builder
COPY --from=builder /venv /venv

# Copy requirements and install dev dependencies
COPY requirements/development.txt /app/requirements/development.txt
RUN . /venv/bin/activate && \
    pip install --no-cache-dir -r requirements/development.txt

# Puts the venv's python (and other executables) at the front of the PATH
ENV PATH=/venv/bin:$PATH

COPY pyproject.toml /app/
COPY ./app ./

RUN /venv/bin/python /app/manage.py collectstatic --no-input

RUN addgroup --system --gid 900 app && \
    adduser --system --uid 900 --ingroup app app

RUN chown -R app /app

USER app

CMD ["/app/scripts/start_app.sh"]

#########################
#
# Production stage - smallest possible runtime image
# Uses slim base and only copies runtime dependencies and the built venv
#
FROM python:3.12-slim as prod

LABEL org.opencontainers.image.source=https://github.com/scanner/as_email_service
LABEL org.opencontainers.image.description="Apricot Systematic Email Service"
LABEL org.opencontainers.image.licenses=BSD-3-Clause

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

ARG APP_HOME=/app
WORKDIR ${APP_HOME}

# Install ONLY runtime dependencies needed by your Python packages
# These are the shared libraries that compiled extensions link against
# NO build tools (gcc, make, etc.) - only runtime libraries
RUN apt-get update && \
    apt-get install --assume-yes --no-install-recommends \
    # PostgreSQL client library (for psycopg2)
    libpq5 \
    # If you use Pillow/imaging, uncomment:
    # libjpeg62-turbo \
    # libfreetype6 \
    # If you use lxml, uncomment:
    # libxml2 \
    # libxslt1.1 \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the cleaned venv from builder
# This venv was built in python:3.12-slim so it's compatible
COPY --from=builder /venv /venv

# Copy pyproject.toml for package metadata
COPY --from=builder /app/pyproject.toml /app/pyproject.toml

# Puts the venv's python at the front of the PATH
ENV PATH=/venv/bin:$PATH

# Copy application code
COPY ./app ./

# Run Django management commands as root (before USER app)
# This generates .pyc files that will be readable by app user
RUN /venv/bin/python /app/manage.py collectstatic --no-input && \
    /venv/bin/python /app/manage.py compile_pyc && \
    /venv/bin/python -m compileall /venv

# Create non-root user
RUN addgroup --system --gid 900 app && \
    adduser --system --uid 900 --ingroup app app

# App user needs to write to staticfiles
RUN chown -R app /app/staticfiles

USER app

CMD ["/app/scripts/start_app.sh"]
