# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-03-04

### Added

- GH-1: IMAP delivery method — forward incoming email to any remote IMAP server with SSL; IMAP credentials are encrypted at rest using `SALT_KEY` (supports key rotation)
- GH-1: Per-delivery-method failure tracking — failed methods are recorded in Redis and retried independently with exponential backoff (10 min to 4 h); after `DELIVERY_RETRY_DAYS` days the method is auto-disabled and the account owner notified by email
- GH-1: Authentication failures disable the delivery method immediately rather than retrying; the owner is notified once per 24-hour window
- GH-1: Fixing a delivery method (PATCH) clears its retry record so the failed message is retried on the next run without waiting for backoff
- GH-1: IMAP credential validation on create, update, and re-enable — the API tests the live connection before saving; re-enabling a disabled method with stale credentials is rejected
- Documentation page now uses the logged-in user's actual email account addresses in configuration examples (SMTP/IMAP username, alias delivery) rather than a generic `SITE_NAME`-based placeholder
- Documentation page shows the user's login email address where it describes failure notification emails
- Navbar brand now shows the logged-in user's username instead of "AS Email"
- Delivery method cards are now collapsible — existing methods start collapsed showing a one-line summary, keeping the UI compact when managing multiple delivery methods

### Changed

- GH-1: `dispatch_incoming_email` now iterates each delivery method individually so a failure on one does not block the others

### Fixed

- Spam score header references corrected from `X-Spam-Score` to `X-Spam-Status` in all UI help text and model field descriptions
- Spam score parsing consolidated into a single `get_spam_score()` utility used by both local delivery and IMAP delivery

## [0.4.1] - 2026-03-02

### Added

- GH-104: Documentation, About, Contact, and Report Issue pages added to the navbar (authenticated users only)
- GH-203: Spam classification on incoming email — each email account has a per-account `scan_incoming_spam` toggle (default on) that runs SpamAssassin via `dispatch_incoming_email()` before delivery; all delivery methods see consistent X-Spam-\* headers

### Changed

- GH-104: Site name moved from navbar to footer (alongside version number); navbar brand now shows a home icon with tooltip

### Fixed

- GH-203: Spam auto-filing now correctly reads the score from `X-Spam-Status` (e.g. `score=8.0`); previously looked for `X-Spam-Score` which SpamAssassin does not add

## [0.4.0] - 2026-02-25

### Added

- GH-161: Multiple delivery methods per email account — each account can now have any combination of `LocalDelivery` (store to MH mailbox) and `AliasToDelivery` (forward to another account) methods, each independently enabled/disabled
- GH-161: REST API endpoints for managing delivery methods at `/api/v1/email_accounts/{pk}/delivery_methods/`
- OpenAPI 3.0 schema generation via drf-spectacular with Swagger UI and ReDoc endpoints
- Email Service Manager UI redesigned around the multiple-delivery-method model with inline edit/save/cancel for both account settings and delivery methods
- Delivery method counts shown on collapsed account cards without requiring expansion
- `sync_provider_aliases` management command re-pushes alias settings (including webhook URLs) to all configured providers — useful after changing `SITE_NAME`
- `ProviderName` StrEnum in the provider package enumerates all registered backend names
- `ForwardEmailBackend.DEFAULT_ALIAS_SETTINGS` class attribute documents and enforces desired per-alias configuration, mirroring the existing `DEFAULT_DOMAIN_SETTINGS` pattern

### Changed

- GH-161: Email account delivery configuration migrated from single `delivery_method` field to polymorphic `DeliveryMethod` subclasses (`LocalDelivery`, `AliasToDelivery`)
- GH-196: `ForwardEmailBackend.create_update_domain()` now fetches the live domain, diffs it against `DEFAULT_DOMAIN_SETTINGS`, and issues a PUT only for fields that have drifted; no-op when settings are already correct
- `ForwardEmailBackend.create_update_email_account()` applies the same idempotent GET → diff → conditional PUT pattern using `DEFAULT_ALIAS_SETTINGS`
- Provider admin: `backend_name` is now a dropdown of registered backends instead of a free-text field
- Provider admin: SMTP server configuration split into separate host and port fields; port accepts any valid port (1–65535, default 25); receive-only providers no longer require an SMTP host

### Fixed

- Delivery method list API now returns subtype-specific fields (e.g. `autofile_spam`, `target_account`) so the UI correctly reflects saved values on page load
- Account cards auto-expand when a user has only one email account

## [0.3.0] - 2025-11-27

### Added

- GH-178: ForwardEmail receive-only provider support
- GH-177: Email provider abstraction layer with configurable send and receive providers, supporting multiple simultaneous receive providers
- Selective enabling/disabling of SMTP (port 25) and submission (port 587) listeners via `--smtp_port off` / `--submission_port off`

## [0.2.6] - 2025-10-21

### Changed

- aiosmtpd now listens on both SMTP port 25 and submission port 587 simultaneously
- Update to Python 3.13

## [0.2.5] - 2025-10-20

### Added

- CLI script for checking spam scores on individual messages

## [0.2.4] - 2025-10-12

### Fixed

- Properly dispatch Huey background tasks from async aiosmtpd handlers

## [0.2.3] - 2025-10-12

### Fixed

- Pre-load related fields on async ORM lookups to avoid additional database queries

## [0.2.2] - 2025-10-11

### Fixed

- Allow local addresses to send email to other local addresses

## [0.2.1] - 2025-10-11

### Changed

- Move IP blocklist rejection to CONNECT phase for earlier and more efficient rejection

## [0.2.0] - 2025-10-11

### Fixed

- `start_smtpd.sh` startup script

## [0.1.23] - 2025-10-11

### Fixed

- Tweaks and test fixes following the incoming email daemon changes

## [0.1.22] - 2025-10-10

### Added

- GH-141: Separate aiosmtpd-based daemon for receiving and delivering incoming email, with spam filtering and DNS blocklist checking
- GH-164: Switch to `uv` for dependency management
- Link to Django admin from the web UI

### Fixed

- Password change button in the web UI

## [0.1.21] - 2024-09-22

### Added

- Automatically re-attempt failed message deliveries

## [0.1.20] - 2024-07-07

### Fixed

- GH-156: Retry delivery on `FileExistsError` instead of failing

## [0.1.19] - 2024-06-30

### Fixed

- GH-153: Message Filter Rule REST endpoint not filtering by email account correctly

## [0.1.18] - 2024-06-30

### Added

- GH-153: Additional filterable header fields in Message Filter Rules

### Fixed

- GH-153: Message Filter Rule list now only shows rules belonging to the requested email account

## [0.1.17] - 2024-06-26

### Fixed

- GH-149: Unicode error when converting message to bytes during delivery

## [0.1.16] - 2024-06-24

### Changed

- GH-149: Move failed incoming deliveries to a dedicated directory instead of discarding them

## [0.1.15] - 2024-06-23

### Fixed

- GH-149: Handle unicode errors when encoding email messages for delivery

## [0.1.14] - 2024-06-16

### Added

- GH-144: Script to import a `.maildelivery` file and convert its rules to Message Filter Rules
- GH-138: Allow email attachments up to 10 MB

## [0.1.13] - 2024-02-01

### Fixed

- GH-121: Admin search fields now work correctly on models without foreign key relations

## [0.1.12] - 2024-02-01

### Fixed

- GH-132: Bounce ID collision when retrying delivery after a delay

## [0.1.11] - 2024-02-01

### Fixed

- GH-130: Lowercase incoming `to` address before lookup to prevent case-sensitivity mismatches
- GH-126: Break out of encoding loop once a working encoding is found

## [0.1.9] - 2024-01-31

### Fixed

- GH-126: Try ascii → utf-8 → latin-1 encoding fallback chain when sending messages

## [0.1.8] - 2024-01-30

### Fixed

- GH-126: Use direct binary conversion when sending messages to correctly handle latin-1 encoded content

## [0.1.7] - 2024-01-29

### Added

- GH-116: Standard mail folders (Drafts, Sent, Trash, Junk) created automatically for new maildirs

### Fixed

- GH-123: Log a warning instead of crashing when `EmailAccount.DoesNotExist` during delivery

## [0.1.6] - 2024-01-28

### Added

- GH-117: Sync external password file when EmailAccounts are created, updated, or deleted

### Changed

- Update to Python 3.12, updated requirements

## [0.1.5 - 2023-11-28]

### Updated

- Now `SENTRY_PROFILES_SAMPLE_RATE` defaults to 0.0 and is settable via .env

## [0.1.4 - 2023-11-26]

### Fixed

- GH-109 - actually use the folder locking context manager on local delivery

## [0.1.3] - 2023-11-26

### Fixed

- in `deliver.py` create contextmanger for locking a mail folder so that if
  another process has it locked it will block and try for some time instead of
  failing immediately

### Updated

- Update to `prettier` v3.1.0
- Update `ruff` to 0.1.6
- Update `black` to 23.11.0
- Lot of other updated requirements

## [0.1.2] - 2023-11-14

### Fixed

- Added 'forgot password' link to the reset pw page.

## [0.1.1] - 2023-11-13

### Added

- GH-92: Added the permission `as_email.can_have_foreign_aliases` on the EmailAccount. Allows users to have `aliases` and `alias_for` entries for EmailAccounts that they do not own. Useful `admin` owned EmailAccounts to be aliased to a non-`admin` owned EmailAccount, or for two different users to have an alias that delivers to both of them
- GH-21: based on the Django settings for `EMAIL_SERVICE_ACCOUNTS` and `EMAIL_SERVICE_ACCOUNTS_OWNER` a set of EmailAccount's will be created when a Server is first saved so that servers get a good default set of administrative email addresses. The default list is "admin", "abuse", "postmaster", "security", "hostmaster", "webmaster", "support", "www", and "noc". Of these all but the first entry in the list ("admin" by default) become aliases to that first entry.

### Fixed

- GH-95: Do not generate a stack trace on a ConnectionResetError in
  aiosmtpd. Just log an error.

## [0.1.0] - 2023-11-10

### Added

- First more or less complete working version except for Message Filter Rule
  editing in the web interface

## [0.0.4] - 2023-10-24

### Added

- Using bulma for css
- Adding sentry.io support
- Added virtual field `aliases` (the reverse of the field `alias_for`). People tend to think "what aliases does this email address have". You can add an alias, or you can say what email accounts this email acount is an alias for, or you can do both. Both fields are exposed.

### Fixed

- GH-53: Every now and then generating the DJANGO_SECRET_KEY during tests would fail because it had a `$` in it.. causing Environ to attempt to look up a variable that does not exist.

## [0.0.1] - 2023-08-02

### Added

- First version that works as a set of services. This is mostly just a
  checkpoint for starting when the service as a whole is first defined
