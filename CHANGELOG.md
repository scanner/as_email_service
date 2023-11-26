# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
