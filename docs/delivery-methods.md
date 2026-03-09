# Delivery Methods

Each `EmailAccount` can have one or more delivery methods attached. Incoming
email is dispatched to every enabled method for that account. Methods are
independent — a failure on one does not prevent delivery via the others.

---

## LocalDelivery

Writes incoming mail to an MH mailbox on the local filesystem. The mailbox
path is derived automatically from the email account address and `MAIL_DIRS`.

**Spam auto-filing** — if `autofile_spam` is enabled and the `X-Spam-Status`
score meets or exceeds `spam_score_threshold`, the message is filed into
`spam_delivery_folder` instead of the inbox.

No configuration beyond the spam settings is required.

---

## AliasToDelivery

Forwards incoming mail to a different `EmailAccount` on the same server.
Useful for consolidating several addresses (e.g. `info@`, `support@`) into one
inbox without managing separate accounts.

Alias chains are resolved recursively. Delivery to each alias target uses that
target's own delivery methods, so aliases can themselves have IMAP delivery,
further aliases, and so on.

---

## ImapDelivery

Delivers incoming mail to a remote IMAP server via SSL. Suitable for
forwarding to Gmail, Fastmail, iCloud Mail, or any hosted or self-hosted IMAP server.

### Provider-specific setup

#### Gmail

Gmail does not allow regular account passwords for IMAP access. You must use
an **app password** — a 16-character password generated specifically for this
purpose.

**Requirements:**

- Your Google Account must have [2-Step Verification](https://myaccount.google.com/signinoptions/two-step-verification) enabled.
- IMAP must be enabled in Gmail settings: **Settings → See all settings → Forwarding and POP/IMAP → IMAP access → Enable IMAP**.

**Generating an app password:**

1. Go to your [Google Account security page](https://myaccount.google.com/security).
2. Under "How you sign in to Google", select **2-Step Verification**.
3. Scroll to the bottom and select **App passwords**.
4. Under "Select app", choose **Mail**. Under "Select device", choose **Other (Custom name)** and enter something like `as_email_service`.
5. Click **Generate**. Copy the 16-character password shown (spaces are optional).

Full instructions: <https://support.google.com/mail/answer/185833?hl=en>

**IMAP settings to use:**

| Field     | Value                                          |
| --------- | ---------------------------------------------- |
| IMAP host | `imap.gmail.com`                               |
| IMAP port | `993`                                          |
| Username  | your full Gmail address (e.g. `you@gmail.com`) |
| Password  | the 16-character app password                  |

> **Note:** App passwords are tied to your Google Account. If you disable
> 2-Step Verification or revoke the app password in your Google Account
> settings, IMAP delivery will fail and the method will be auto-disabled after
> the retry window.

---

#### iCloud Mail

iCloud Mail requires an **app-specific password** for third-party IMAP access.
Your regular Apple ID password will not work.

**Requirements:**

- Your Apple ID must have [two-factor authentication](https://support.apple.com/en-us/104232) enabled.
- IMAP access must be enabled: in iCloud.com, go to **Mail → Settings (gear icon) → Preferences → Account** and confirm IMAP access is on. On a Mac: **System Settings → Apple ID → iCloud → iCloud Mail** must be turned on.

**Generating an app-specific password:**

1. Go to [appleid.apple.com](https://appleid.apple.com) and sign in.
2. In the **Sign-In and Security** section, select **App-Specific Passwords**.
3. Click the **+** button and enter a label (e.g. `as_email_service`).
4. Click **Create**. Copy the password shown (format: `xxxx-xxxx-xxxx-xxxx`).

Full instructions: <https://support.apple.com/en-us/102525>

**IMAP settings to use:**

| Field     | Value                                                                             |
| --------- | --------------------------------------------------------------------------------- |
| IMAP host | `imap.mail.me.com`                                                                |
| IMAP port | `993`                                                                             |
| Username  | your iCloud email address (e.g. `you@icloud.com`, `you@me.com`, or `you@mac.com`) |
| Password  | the app-specific password                                                         |

> **Note:** App-specific passwords are tied to your Apple ID. Revoking the
> password in your Apple ID account settings will cause IMAP delivery to fail.

---

### Credential storage

IMAP usernames and passwords are encrypted at rest using
[django-fernet-encrypted-fields](https://github.com/jazzband/django-fernet-encrypted-fields).
Encryption keys are derived from `SECRET_KEY` + `SALT_KEY` via PBKDF2-SHA256.

**Required `.env` setting:**

```ini
# Generate with: python -c "import secrets; print(secrets.token_hex(32))"
SALT_KEY=<hex string>
```

**Key rotation** — set `SALT_KEY` to a comma-separated list. The first value
encrypts new data; remaining values decrypt existing records. Once all records
have been re-encrypted with the new key, remove the old one.

### Spam auto-filing

When `autofile_spam` is enabled and the spam score meets `spam_score_threshold`,
the message is appended to the remote junk folder. Resolution order:

1. A folder with the IMAP `\Junk` or `\Spam` SPECIAL-USE flag (RFC 6154).
2. A folder literally named `Junk`.
3. `INBOX` — the message is still delivered, just not auto-filed.

### Credential validation

Credentials are tested against the live IMAP server in two situations:

- **On create or PATCH with a new password** — the API rejects bad credentials
  before saving.
- **On re-enable** — when a PATCH sets `enabled = true` on a disabled
  `ImapDelivery`, the stored credentials are tested. The request is rejected
  with HTTP 400 if the connection fails, preventing the method from being
  re-enabled with stale credentials.

---

## Retry tracking for failing methods

`LocalDelivery` always succeeds (it writes to a local disk). Methods that
contact external services (`ImapDelivery`) can fail transiently. The service
tracks these failures in Redis and retries automatically.

### Redis key schema

```
delivery_retry:{file-stem}          — hash, one per failed message file
  first_failure     ISO-8601 UTC    first time any method failed for this file
  attempt_count     integer string  total delivery attempts so far
  failed_method_pks JSON list       PKs of methods that failed on the last attempt
  next_retry_at     ISO-8601 UTC    earliest time the next retry should run

delivery_notify:{method-pk}         — plain string, TTL = 24 h
                                      presence suppresses repeat owner notifications
```

### Backoff schedule

The retry task runs every 10 minutes. Between failures the wait doubles,
capped at 4 hours:

| Attempt | Wait   |
| ------- | ------ |
| 1       | 10 min |
| 2       | 20 min |
| 3       | 40 min |
| 4       | 80 min |
| 5+      | 4 h    |

The task skips a file until the current time passes `next_retry_at`.

### Auto-disable after the retry window

If a method is still failing after `DELIVERY_RETRY_DAYS` (default 7, set via
`.env`):

1. The method is disabled (`enabled = False`).
2. A Delivery Status Notification (DSN, RFC 3464) is sent to the email account.
3. A plain-text warning is emailed to the Django `User` who owns the account.
4. The retry record and failed message file are deleted.

### Authentication failures

When the exception message indicates a credential problem (keywords:
`authentication`, `credentials`, `login failed`, `not authenticated`,
`authenticationfailed`), the method is auto-disabled immediately without
waiting for the retry window. A notification is sent once; subsequent
failures within 24 hours are suppressed via the `delivery_notify:{pk}` key.

### Clearing the retry record on update

When a delivery method is updated via PATCH, any `delivery_retry:*` hashes
referencing its PK are deleted. The failed message is then retried on the
next 10-minute run without waiting for the backoff timer.

---

## Settings reference

| Variable              | Default | Description                                                 |
| --------------------- | ------- | ----------------------------------------------------------- |
| `SALT_KEY`            | —       | Required. Salt for IMAP credential encryption. See above.   |
| `DELIVERY_RETRY_DAYS` | `7`     | Days before a persistently failing method is auto-disabled. |
