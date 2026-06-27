# Email Change -- Security Design

This document describes the email change flow implemented in `as_email_service`
and the models and signals that enforce it.

---

## User-facing flow

1. The user navigates to **Account Info** and submits a new email address.
2. Two emails are sent simultaneously:
   - A **cancellation email** to the _current_ (old) address, containing a
     one-click revocation link valid for 7 days. No login is required to cancel.
   - A **verification email** to the _new_ address (sent by allauth).
     The confirmation link expires in 24 hours.
3. If the user clicks the confirmation link, the new address becomes primary
   and a 7-day cooldown begins. No further email changes are possible during
   the cooldown. An admin can lift it early by deleting the `EmailChangeCooldown`
   record in the Django admin.
4. If the user or anyone with access to the old inbox clicks the cancellation
   link (within 7 days), the pending change is aborted and the unverified new
   address is removed. The confirmation link in the new inbox immediately stops
   working.

If access to either address is lost before completing the flow, the user must
contact support.

---

## Models (`users/models.py`)

### `PendingEmailChange`

Created when a new address is submitted (via the `email_added` allauth signal).
Deleted when the change is confirmed or revoked.

| Field            | Purpose                                                                 |
| ---------------- | ----------------------------------------------------------------------- |
| `user`           | OneToOne FK -- at most one pending change per user                      |
| `new_email`      | The address awaiting confirmation                                       |
| `revocation_key` | URL-safe random token embedded in the cancellation link                 |
| `expires_at`     | 7 days after creation; governs when the cancellation link stops working |

`PendingEmailChange.create_for_user(user, new_email)` uses `update_or_create`
so resubmitting a new address replaces the previous record and issues a fresh
cancellation link.

### `EmailChangeCooldown`

Created when a change is confirmed (via the `email_changed` allauth signal).
Blocks further changes for 7 days. `is_active` returns `True` until `expires_at`
is reached. The view auto-deletes expired records on next page load.

---

## Signal handlers (`users/signals.py`)

| Signal                                  | Handler            | Action                                                                |
| --------------------------------------- | ------------------ | --------------------------------------------------------------------- |
| `allauth.account.signals.email_added`   | `on_email_added`   | Creates `PendingEmailChange`; sends cancellation email to old address |
| `allauth.account.signals.email_changed` | `on_email_changed` | Deletes `PendingEmailChange`; creates `EmailChangeCooldown`           |

`on_email_added` skips silently when `request is None` (admin/management-command
context -- there is no URL to build for the cancellation link) or when the user
has no verified primary address to notify (genuine first-time setup).

---

## Views

### `AccountInfoView` (`as_email/account_views.py`)

Wraps allauth's `EmailView`. On `GET`, injects `email_change_cooldown_until`
into the template context if an active cooldown exists (stale expired records
are deleted). On `POST` (form submission), re-checks the cooldown server-side
even if the UI hid the form.

### `AccountPasswordChangeView`

Wraps allauth's `PasswordChangeView` to render `account_info.html` on both
success and failure, so the full Account Info page (email + password sections)
is always displayed. On error it re-populates the email section context so the
page renders correctly.

### `EmailChangeRevokeView`

No login required -- the revocation key is the authentication token.

- `GET` -- renders a confirmation page ("cancel this change?") without mutating
  state. This avoids corporate email security gateways (Proofpoint, Safe Links)
  that prefetch links in messages via GET, which would otherwise silently cancel
  legitimate change requests.
- `POST` -- deletes the `PendingEmailChange` record and removes the unverified
  `EmailAddress` from allauth so the confirmation link becomes invalid.

URL: `as_email:email_change_revoke` at `email-change/revoke/<str:key>/`

---

## Email templates

| Template                                       | Recipient   | Purpose                                                                          |
| ---------------------------------------------- | ----------- | -------------------------------------------------------------------------------- |
| `users/email/email_change_pending_subject.txt` | Old address | Subject line for the cancellation notice                                         |
| `users/email/email_change_pending_message.txt` | Old address | Body: describes the pending change, provides the revocation URL                  |
| allauth defaults                               | New address | Standard allauth verification email                                              |
| allauth defaults                               | Old address | Standard allauth "email changed" security notification (sent after confirmation) |

---

## Admin

Both `PendingEmailChange` and `EmailChangeCooldown` are registered in the Django
admin. To lift a cooldown early, delete the relevant `EmailChangeCooldown` record.
