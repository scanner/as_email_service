# as_email_service -- Docker Compose Deployment

This directory is a complete deployment of as_email_service with Docker
Compose, for production, staging or integration hosts. Copy it to the host,
fill in `.env` and `secrets/`, and start it. Nothing here is used by local
development, which uses `docker-compose.yml` at the repo root.

The stack pulls the pre-built image from GHCR
(`ghcr.io/scanner/as_email_service`) and runs:

- `web` -- runs the migrations, then the web UI, the REST API and the
  providers' webhooks, published on localhost for a TLS reverse proxy
- `smtpd` -- SMTP submission on port 587
- `worker` -- the huey worker: delivery, retries and periodic tasks
- `spamassassin` -- spamd, which `smtpd` scans incoming mail through
- `sa-training` -- an on-demand job that stages user-reported spam and ham
  (the `tools` profile, so `docker compose up` does not start it)

Redis is external, reached over the `redis_network` Docker network.

---

## Directory layout

```
deployment/compose/
  docker-compose.yml    # the stack
  dot-env.example       # non-secret config template -- copy to .env
  secrets/              # secret files (gitignored except .gitkeep)
  README.md             # this file
```

---

## 1. Prepare the host directories

The services run as the unprivileged `app` user, UID 900. Create the
directories named in `.env` and give them to UID 900:

```sh
sudo install -d -o 900 -g 900 -m 0755 \
    /srv/as_email/dbs /srv/as_email/spool /srv/as_email/mail_dirs \
    /srv/as_email/ssl /var/log/as_email
sudo install -d -m 0755 /srv/as_email/spama \
    /srv/as_email/spama/home /srv/as_email/spama/logs \
    /srv/as_email/spama/training
```

`HOST_MAIL_ROOT` is the mail store asimap serves. as_email_service writes
each account's mail directory there and the IMAP password file,
`asimapd_passwords.txt`, at its root. Mount the same directory into asimap
at `/opt/asimap`.

`HOST_SPAMA_DIR` must hold SpamAssassin's `local.cf` and `local.pre` before
the stack starts. A missing file would be created as an empty directory by
the bind mount.

---

## 2. Install the TLS certificate

`smtpd` offers STARTTLS with `ssl_crt.pem` and `ssl_key.pem` from
`HOST_SSL_DIR`:

```sh
sudo install -o 900 -g 900 -m 0644 fullchain.pem /srv/as_email/ssl/ssl_crt.pem
sudo install -o 900 -g 900 -m 0600 privkey.pem   /srv/as_email/ssl/ssl_key.pem
```

`smtpd` reads the certificate at startup, so restart it after replacing the
files: `docker compose restart smtpd`. With certbot, a deploy hook in
`/etc/letsencrypt/renewal-hooks/deploy/` that runs both steps keeps the
served certificate current across renewals.

`web` serves plain HTTP. Put a reverse proxy that terminates TLS in front of
it, sending `X-Forwarded-Proto: https`.

---

## 3. Create the secret files

Each file holds one value with no trailing newline, and is read by UID 900:

```sh
cd secrets

# Django signing key -- generate with:
#   python3 -c "import secrets; print(secrets.token_hex(50), end='')"
printf '%s' 'YOURKEY' > django_secret_key

# Key derivation salt for the encrypted fields -- generate with:
#   python3 -c "import secrets; print(secrets.token_hex(32), end='')"
printf '%s' 'YOURSALT' > salt_key

# The providers' API keys, as one JSON object.  Each provider has an
# "account_api_key" plus one key per domain it sends for.
printf '%s' '{"postmark":{"account_api_key":"...","example.com":"..."},"forwardemail":{"account_api_key":"...","example.com":"..."}}' \
    > email_server_tokens

# Credentials for EMAIL_BACKEND, as comma-separated key=value pairs.
printf '%s' 'POSTMARK_SERVER_TOKEN=...' > anymail

# The Sentry DSN, or an empty file to run without Sentry.
printf '%s' 'https://examplePublicKey@o0.ingest.sentry.io/0' > sentry_dsn

sudo chown 900:900 *
sudo chmod 0600 *
```

`printf` (not `echo`) avoids the trailing newline. A newline at the end of
`salt_key` would become part of its last salt.

Compose bind-mounts each file at `/run/secrets/<name>`, and django-environ
reads it through the matching `<NAME>_FILE` variable. The files keep their
host ownership inside the containers, which is why UID 900 owns them.

Every file must exist, even an empty `sentry_dsn`: Compose refuses to start
a service whose secret file is missing.

`SECRET_KEY` and `SALT_KEY` together derive the key that encrypts stored
IMAP credentials, so changing either one makes those values unreadable. To
rotate the salt, write the new salt first and keep the old one after it,
comma-separated; see `SALT_KEY` in `app/config/settings.py`.

---

## 4. Configure .env

```sh
cp dot-env.example .env
$EDITOR .env
```

Set at minimum `VERSION`, the `HOST_*` directories, `SITE_NAME`,
`ALLOWED_HOSTS` and the email settings. `ALLOWED_HOSTS` also sets the
trusted CSRF origins, as `https://<host>` for each one.

Redis: the start scripts wait for the host `redis`, and huey uses database 1
of that server. Point `CACHE_URL` at a different database, and keep both
clear of any other service sharing the Redis server.

---

## 5. Start the stack

```sh
docker compose pull
docker compose up -d
docker compose logs -f web smtpd worker
```

`web` runs the database migrations each time it starts.

---

## 6. Smoke test

```sh
# The web UI, through the reverse proxy
curl -sI https://mail.example.com/ | head -1

# The certificate smtpd offers
openssl s_client -connect mail.example.com:587 -starttls smtp \
    -servername mail.example.com </dev/null 2>/dev/null \
    | openssl x509 -noout -subject -enddate
```

Then send a message from a mail client through port 587, and check that it
arrives in a local account.

---

## 7. Spam training

Run the training job by hand or from cron:

```sh
docker compose run --rm sa-training
```

See [`docs/sa-training.md`](../../docs/sa-training.md) for the whole
pipeline, including `sa-learn` and rule updates in the `spamassassin`
container.

---

## 8. Updating and rollback

Edit `.env` to set the version to run, then pull and recreate:

```sh
# In .env: VERSION=0.10.2
docker compose pull
docker compose up -d
```

The migrations only go forward. Rolling back is the same steps with the
previous version, as long as no release in between added a migration;
otherwise restore the database from a backup taken before the upgrade.

To change a secret, rewrite its file and recreate the containers:
`docker compose up -d --force-recreate`. A plain restart keeps the old file,
because the bind mount holds the file that was there when the container was
created.
