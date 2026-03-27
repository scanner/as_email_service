# SpamAssassin Training

This document describes how to set up user-driven SpamAssassin training,
allowing users to report misclassified messages by forwarding them to
dedicated email addresses.

## Overview

Users forward missed spam to a **spam** address and false positives to a
**not-spam** address. A management command processes these submissions,
extracts the original messages, and stages them in directories that
`sa-learn` can consume.

## Setup

### 1. Environment variables

Add the following to your deployment environment:

```
SPAM_TRAINING_ADDRESS=spam@mail.example.com
NOT_SPAM_TRAINING_ADDRESS=not-spam@mail.example.com
```

Both must be set for the feature to work. The addresses will also appear
on the user-facing documentation page automatically.

### 2. Create the email accounts

On the server that will handle training submissions, create two email
accounts:

- `spam@<server>` — with **Local Delivery** enabled
- `not-spam@<server>` — with an **Alias** delivery pointing to
  `spam@<server>` (so both addresses deliver to the same inbox)

On the account that has Local Delivery (e.g. `spam@<server>`):

- **Disable** "Scan incoming email for spam" (`scan_incoming_spam = False`).
  Training messages include both known-spam and known-ham; scanning them
  would interfere with the forwarded content.
- **Disable** "Auto-file spam" (`autofile_spam = False`) on the
  LocalDelivery so all messages land in the inbox regardless of headers.

### 3. Running the command

A dedicated `sa-training` service is defined in `docker-compose.yml`
under the `tools` profile. It mounts the mail directories and the
SpamAssassin training directory (`./spama/training` → `/mnt/training`):

```bash
docker compose run --rm sa-training
```

This reads messages from the training inbox and writes extracted
originals as numbered files into `/mnt/training/spam/` and
`/mnt/training/ham/` — the same directories the `spamassassin` container
has mounted at `/mnt/training`.

If you need to override the training directory:

```bash
docker compose run --rm sa-training \
  /app/manage.py as_email_sa_training /some/other/path
```

### 4. Feeding sa-learn

After the management command has staged the messages, run `sa-learn`
inside the spamassassin container:

```bash
docker compose exec spamassassin sa-learn --spam /mnt/training/spam/
docker compose exec spamassassin sa-learn --ham /mnt/training/ham/
```

It is safe to run `sa-learn` repeatedly on the same directory.
SpamAssassin tracks which messages it has already learned in its
`bayes_seen` database and will not re-learn them. This means training
messages can be kept on disk as a permanent corpus — useful if you ever
need to retrain after a database reset or `bayes_expire`.

If disk space becomes a concern, old training messages can be removed
at your discretion.

## Initial / Manual Training

If you have an existing corpus of spam and ham, or need to retrain after a
Bayes database reset, run `sa-learn` directly inside the `spamassassin`
container. The default `docker-compose.yml` mounts the training data at
`/mnt/training`:

```bash
docker compose exec spamassassin sa-update
docker compose exec spamassassin sa-learn --spam /mnt/training/spam/
docker compose exec spamassassin sa-learn --ham /mnt/training/ham/
docker compose exec spamassassin sa-learn --sync
```

Place your pre-existing spam corpus under `./spama/training/spam/` and ham
under `./spama/training/ham/` on the host before running these commands. If
you mount the training directory somewhere else, adjust the paths accordingly.

**NOTE**: Training a large corpus can take a few minutes per `sa-learn` call.
The `--sync` step flushes journalled changes to the Bayes database and should
be run after each batch, especially before restarting the container.

## How it works

1. The command looks up the `LocalDelivery` for the configured training
   addresses and opens the MH inbox.
2. For each message in the inbox:
   - **Sender validation** — the `From` address must belong to an enabled
     `EmailAccount` on this instance. Messages from unknown senders are
     discarded.
   - **Classification** — recipient headers (`Delivered-To`,
     `X-Original-To`, `To`, `Envelope-To`) are checked to determine
     whether the user forwarded to the spam or not-spam address.
   - **Extraction** — if the message contains a `message/rfc822`
     attachment (forward-as-attachment or SA-processed false positive),
     the attached original is extracted. Otherwise the full forwarded
     message is used as-is (inline forward).
3. Extracted messages are written as numbered files to the appropriate
   `spam/` or `ham/` subdirectory and removed from the inbox.

## Docker Compose service

The `sa-training` service is configured with the `tools` profile so it
does not start with `docker compose up`:

```yaml
sa-training:
  image: as_email_service:dev
  profiles:
    - tools
  env_file: .env
  volumes:
    - "${HOST_DB_DIR}:/mnt/db:z"
    - "${HOST_MAIL_ROOT}:/mnt/mail_dirs:z"
    - "${HOST_SPAMA_DIR:-./spama}/training:/mnt/training:z"
  command: /app/manage.py as_email_sa_training /mnt/training
```

The `./spama/training` directory is shared with the `spamassassin`
container (also mounted at `/mnt/training`), so messages staged by
the management command are immediately available to `sa-learn`.
