# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Security logging for fail2ban integration: structured log output for auth failures, connection floods, DNSBL rejections, and protocol errors
- `PROTECTED_ACCOUNTS` setting for accounts (e.g. admin@, root@) that trigger immediate bans on wrong password
- Per-IP connection flood detection (>10 connections in 60s)
- Example fail2ban filters, jails, and setup documentation (`docs/fail2ban-integration.md`)
- Report framework (`as_email.reports`) with registry, schedule metadata, and staggered task execution
- Management command `as_email_report` to run any registered report by name (`as_email_report email-usage`, `as_email_report --list`)
- Email usage report for per-account mailbox usage and orphaned mail directory detection

### Changed

- Move unused servers report into the report framework
- Daily and weekly report tasks now stagger individual report execution to avoid running all reports simultaneously

### Fixed

- Fix `UnboundLocalError` in unused servers report when a provider has no receiving servers (AS-EMAIL-SERVICE-3D)

## [0.6.3] - 2026-03-22

### Fixed

- Fix race condition where signal-dispatched Huey tasks could run before the DB transaction committed, causing `DoesNotExist` errors (AS-EMAIL-SERVICE-3E)

### Changed

- Replace black + isort with ruff for formatting and import sorting (GH-199)
- Enable stricter mypy settings (`check_untyped_defs`, `warn_unused_ignores`, `warn_redundant_casts`) and fix all resulting type errors
- Fix real bug in `handle_RCPT` where a redundant `.lower()` call on a `None` value would raise at runtime

### Removed

- Drop black, isort, yapf, autopep8, and flake8 from dev dependencies

## [0.6.2] - 2026-03-18

### Fixed

- Fix unused servers report where the list was reset on each iteration, causing only the last server to appear in the report

## [0.6.1] - 2026-03-16

### Changed

- Postmark bounce and spam webhooks now use the unified `process_bounce` Huey task via `BounceEvent`, replacing the Postmark-specific `process_email_bounce` and `process_email_spam` tasks (GH-223)
- Hourly EmailAccount/alias sync now spreads work across a 4-hour window: each server/provider pair is synced at most once per 4 hours, with the 3 least-recently-synced pairs dispatched per run; a Sentry error alert fires if any pair goes 24 hours without a successful sync
- ForwardEmail API rate-limit state is now process-global and thread-safe — all `APIClient` instances within the same process share one `RateLimiter` per provider, so rate-limit headers from one request inform throttling for all subsequent requests
- Network-unreachable errors in provider sync tasks are now logged as warnings and do not trigger Huey retries; the hourly scheduler retries naturally on the next run
- Removed Huey task-level retries from `provider_sync_server_email_accounts`; the hourly staleness-based scheduling serves as the retry mechanism

### Removed

- `process_email_bounce` and `process_email_spam` Huey tasks; all providers now use the provider-agnostic `process_bounce` task

## [0.6.0] - 2026-03-14

### Added

- ForwardEmail.net backend is now a full send/receive provider: outbound email is sent via the ForwardEmail REST API using the account API key
- `BounceEvent` dataclass in `providers/base.py` normalizes bounce and spam events across provider backends; lays the foundation for unified bounce/spam processing (GH-223)
- `process_bounce` Huey task provides provider-agnostic bounce and spam complaint handling: permanent-bounce counting, `InactiveEmail` recording, account deactivation at the bounce limit, owner notification, and DSN delivery
- ForwardEmail bounce webhook now handles both delivery bounces and spam complaints (ForwardEmail delivers both to the same webhook endpoint, distinguished by `bounce.category`)
- `get_bounce_webhook_url(server)` on `ForwardEmailBackend` builds the per-domain webhook URL; `create_update_domain()` registers it with the ForwardEmail API on every domain create/update
- `sync_provider_domains` management command syncs domain configuration across providers with `--domain`, `--provider`, and `--dry-run` options
- Daily periodic task re-syncs domain settings on all configured providers, catching configuration drift

### Changed

- Unified outbound email sending behind `Server.send_email()`, letting each provider backend pick the transport method (SMTP relay or REST API) it determines is most suitable
- `email_from` and `rcpt_tos` are now optional across all provider send methods; a shared `resolve_envelope()` utility extracts them from message headers when not provided
- Removed redundant `create_domain()` from the provider backend interface; `create_update_domain()` handles both creation and updates

### Fixed

- Transient bounces (temporary deferrals) no longer trigger account deactivation even when the permanent-bounce counter is already at its ceiling
- `delete_email_account_by_address()` signature in `ProviderBackend` corrected to `server: Server` (was `domain_name: str`), consistent with all other provider methods

## [0.5.8] - 2026-03-15

### Fixed

- Fix UnicodeEncodeError when scanning or delivering emails with non-ASCII content but no charset declaration (common in spam)
- Spam scan failures now log at ERROR level so unexpected issues generate Sentry alerts

## [0.5.7] - 2026-03-15

### Fixed

- SMTP session exceptions from misbehaving or abruptly disconnecting clients are now logged at WARNING instead of ERROR, preventing spurious Sentry alerts

## [0.5.6] - 2026-03-09

### Added

- Admin navbar link is now visible to members of the "admin" group in addition to superusers; `is_in_group` template filter added

## [0.5.5] - 2026-03-09

### Added

- Documentation page now includes step-by-step instructions for obtaining app passwords for Gmail and iCloud Mail for use with IMAP delivery
- Documentation page now shows an annotated screenshot of the email account card to clarify where the SMTP/IMAP username and password are set

### Changed

- Documentation page makes the two-password distinction (web login vs. email account) explicit with a prominent callout and troubleshooting tip
- Failure notification emails are sent to the web login address, which is now identified as such in the documentation (it may differ from any email account on the server)

## [0.5.4] - 2026-03-08

### Added

- Provider capability system (`Capability` enum + `CAPABILITIES` class attribute on `ProviderBackend`) makes provider-specific dispatch explicit and extensible

### Changed

- Renamed `provider_sync_server_aliases` to `provider_sync_server_email_accounts` and `provider_sync_email_accounts` to `provider_sync_all_email_accounts` to better reflect their purpose
- `provider_create_email_account` renamed to `provider_create_or_update_email_account`; it now also fires when `EmailAccount.enabled` changes, immediately propagating enable/disable to the provider
- ForwardEmail alias sync now enforces `is_enabled` to match `EmailAccount.enabled` on every sync cycle
- `provider_sync_server_email_accounts(enabled=False)` is a no-op for providers that do not manage per-account entities (e.g. Postmark); for ForwardEmail, all remote accounts are deleted when a provider is removed from a server

### Fixed

- ForwardEmail alias updates now send the complete desired state in the PUT request, preventing fields omitted from the diff from being silently cleared by the API
- Incoming webhooks now reject mail for disabled `EmailAccount`s, preventing delivery to accounts that have been disabled in the system

## [0.5.3] - 2026-03-08

### Fixed

- ForwardEmail alias sync no longer issues spurious PUTs every hour for aliases that are already correct

## [0.5.2] - 2026-03-08

### Fixed

- ForwardEmail aliases that have drifted from the expected configuration (e.g. stale webhook URL in `recipients`) are now detected and corrected during the periodic alias sync

### Changed

- Email account sync (`provider_sync_server_email_accounts`, formerly `provider_sync_server_aliases`) now delegates full verification and repair to `create_update_email_account` rather than only checking enabled state
- `create_update_email_account` on ForwardEmail now caches the full alias data in Redis (warmed by `list_email_accounts`), skipping the GET request when data is already available; issues a PUT only when settings differ
- Redis cache keys for alias data expire automatically (alias data: 2 h, alias/domain IDs: 24 h) to prevent unbounded stale entries

## [0.5.1] - 2026-03-06

### Fixed

- ForwardEmail domain/alias creation now sends requests as JSON instead of form-encoded data, fixing a 400 error caused by Python booleans being serialised as `"True"`/`"False"` strings instead of JSON `true`/`false`

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
