# AS Email Service API

REST API for managing email accounts, message filter rules, and delivery methods in the Apricot Systematic Email Service.

**Version:** 1.0.0

## Authentication

- **basicAuth**: `http` (in: `, name: `)
- **sessionAuth**: `apiKey` (in: `cookie`, name: `sessionid`)

## Endpoints

### v1

#### `GET /as_email/api/v1/email_accounts/`

**Operation:** `v1_email_accounts_list`

The EmailAccount. This represents an email address active on a server.
A user may have multiple EmailAccounts.

NOTE: The EmailAccount can not be created or deleted via the REST API.

**Response 200:**

#### `GET /as_email/api/v1/email_accounts/{email_account_pk}/delivery_methods/`

**Operation:** `v1_email_accounts_delivery_methods_list`

List all delivery methods for the email account.

**Parameters:**

- `email_account_pk` (path, required)

**Response 200:**

#### `POST /as_email/api/v1/email_accounts/{email_account_pk}/delivery_methods/`

**Operation:** `v1_email_accounts_delivery_methods_create`

Create a new delivery method. Include `delivery_type` ("LocalDelivery" or "AliasToDelivery") to select the subtype.

**Parameters:**

- `email_account_pk` (path, required)

**Request Body** (`application/json`):

One of:

- `LocalDeliveryRequest`
- `AliasToDeliveryRequest`

**Request Body** (`application/x-www-form-urlencoded`):

One of:

- `LocalDeliveryRequest`
- `AliasToDeliveryRequest`

**Request Body** (`multipart/form-data`):

One of:

- `LocalDeliveryRequest`
- `AliasToDeliveryRequest`

**Response 201:**

One of:

- `LocalDelivery`
- `AliasToDelivery`

#### `GET /as_email/api/v1/email_accounts/{email_account_pk}/delivery_methods/{id}/`

**Operation:** `v1_email_accounts_delivery_methods_retrieve`

Retrieve a specific delivery method.

**Parameters:**

- `email_account_pk` (path, required)
- `id` (path, required) — A unique integer value identifying this delivery method.

**Response 200:**

One of:

- `LocalDelivery`
- `AliasToDelivery`

#### `PUT /as_email/api/v1/email_accounts/{email_account_pk}/delivery_methods/{id}/`

**Operation:** `v1_email_accounts_delivery_methods_update`

CRUD + ordering for DeliveryMethod objects nested under an EmailAccount.

Supports LocalDelivery and AliasToDelivery subtypes. The request body
must include a `delivery_type` field (e.g. "LocalDelivery") to select
the correct subtype serializer on create/update.

**Parameters:**

- `email_account_pk` (path, required)
- `id` (path, required) — A unique integer value identifying this delivery method.

**Request Body** (`application/json`):

One of:

- `LocalDeliveryRequest`
- `AliasToDeliveryRequest`

**Request Body** (`application/x-www-form-urlencoded`):

One of:

- `LocalDeliveryRequest`
- `AliasToDeliveryRequest`

**Request Body** (`multipart/form-data`):

One of:

- `LocalDeliveryRequest`
- `AliasToDeliveryRequest`

**Response 200:**

One of:

- `LocalDelivery`
- `AliasToDelivery`

#### `PATCH /as_email/api/v1/email_accounts/{email_account_pk}/delivery_methods/{id}/`

**Operation:** `v1_email_accounts_delivery_methods_partial_update`

CRUD + ordering for DeliveryMethod objects nested under an EmailAccount.

Supports LocalDelivery and AliasToDelivery subtypes. The request body
must include a `delivery_type` field (e.g. "LocalDelivery") to select
the correct subtype serializer on create/update.

**Parameters:**

- `email_account_pk` (path, required)
- `id` (path, required) — A unique integer value identifying this delivery method.

**Request Body** (`application/json`):

One of:

- `PatchedLocalDeliveryRequest`
- `PatchedAliasToDeliveryRequest`

**Request Body** (`application/x-www-form-urlencoded`):

One of:

- `PatchedLocalDeliveryRequest`
- `PatchedAliasToDeliveryRequest`

**Request Body** (`multipart/form-data`):

One of:

- `PatchedLocalDeliveryRequest`
- `PatchedAliasToDeliveryRequest`

**Response 200:**

One of:

- `LocalDelivery`
- `AliasToDelivery`

#### `DELETE /as_email/api/v1/email_accounts/{email_account_pk}/delivery_methods/{id}/`

**Operation:** `v1_email_accounts_delivery_methods_destroy`

CRUD + ordering for DeliveryMethod objects nested under an EmailAccount.

Supports LocalDelivery and AliasToDelivery subtypes. The request body
must include a `delivery_type` field (e.g. "LocalDelivery") to select
the correct subtype serializer on create/update.

**Parameters:**

- `email_account_pk` (path, required)
- `id` (path, required) — A unique integer value identifying this delivery method.

**Response 204:** No response body

#### `GET /as_email/api/v1/email_accounts/{email_account_pk}/message_filter_rules/`

**Operation:** `v1_email_accounts_message_filter_rules_list`

**Parameters:**

- `email_account_pk` (path, required)

**Response 200:**

#### `POST /as_email/api/v1/email_accounts/{email_account_pk}/message_filter_rules/`

**Operation:** `v1_email_accounts_message_filter_rules_create`

MessageFilterRule's are nested objects. The view passes in the
required information about the EmailAccount that this MessageFilterRule
belongs to. So we need to make sure that this value is set when
creating.

**Parameters:**

- `email_account_pk` (path, required)

**Request Body** (`application/json`):

- **`header`** (``)
- **`pattern`** (`string`) _(required)_
- **`action`** (`string`) — \* `folder` - folder

* `destroy` - destroy Enum: ['folder', 'destroy']

- **`destination`** (`string`)

**Request Body** (`application/x-www-form-urlencoded`):

- **`header`** (``)
- **`pattern`** (`string`) _(required)_
- **`action`** (`string`) — \* `folder` - folder

* `destroy` - destroy Enum: ['folder', 'destroy']

- **`destination`** (`string`)

**Request Body** (`multipart/form-data`):

- **`header`** (``)
- **`pattern`** (`string`) _(required)_
- **`action`** (`string`) — \* `folder` - folder

* `destroy` - destroy Enum: ['folder', 'destroy']

- **`destination`** (`string`)

**Response 201:**

- **`url`** (`string`) _(required, read-only)_
- **`email_account`** (`string`) _(required, read-only)_
- **`header`** (``)
- **`pattern`** (`string`) _(required)_
- **`action`** (`string`) — \* `folder` - folder

* `destroy` - destroy Enum: ['folder', 'destroy']

- **`destination`** (`string`)
- **`order`** (`integer`) _(required, read-only)_
- **`created_at`** (`string`) _(required, read-only)_
- **`modified_at`** (`string`) _(required, read-only)_

#### `GET /as_email/api/v1/email_accounts/{email_account_pk}/message_filter_rules/{id}/`

**Operation:** `v1_email_accounts_message_filter_rules_retrieve`

**Parameters:**

- `email_account_pk` (path, required)
- `id` (path, required) — A unique integer value identifying this message filter rule.

**Response 200:**

- **`url`** (`string`) _(required, read-only)_
- **`email_account`** (`string`) _(required, read-only)_
- **`header`** (``)
- **`pattern`** (`string`) _(required)_
- **`action`** (`string`) — \* `folder` - folder

* `destroy` - destroy Enum: ['folder', 'destroy']

- **`destination`** (`string`)
- **`order`** (`integer`) _(required, read-only)_
- **`created_at`** (`string`) _(required, read-only)_
- **`modified_at`** (`string`) _(required, read-only)_

#### `PUT /as_email/api/v1/email_accounts/{email_account_pk}/message_filter_rules/{id}/`

**Operation:** `v1_email_accounts_message_filter_rules_update`

**Parameters:**

- `email_account_pk` (path, required)
- `id` (path, required) — A unique integer value identifying this message filter rule.

**Request Body** (`application/json`):

- **`header`** (``)
- **`pattern`** (`string`) _(required)_
- **`action`** (`string`) — \* `folder` - folder

* `destroy` - destroy Enum: ['folder', 'destroy']

- **`destination`** (`string`)

**Request Body** (`application/x-www-form-urlencoded`):

- **`header`** (``)
- **`pattern`** (`string`) _(required)_
- **`action`** (`string`) — \* `folder` - folder

* `destroy` - destroy Enum: ['folder', 'destroy']

- **`destination`** (`string`)

**Request Body** (`multipart/form-data`):

- **`header`** (``)
- **`pattern`** (`string`) _(required)_
- **`action`** (`string`) — \* `folder` - folder

* `destroy` - destroy Enum: ['folder', 'destroy']

- **`destination`** (`string`)

**Response 200:**

- **`url`** (`string`) _(required, read-only)_
- **`email_account`** (`string`) _(required, read-only)_
- **`header`** (``)
- **`pattern`** (`string`) _(required)_
- **`action`** (`string`) — \* `folder` - folder

* `destroy` - destroy Enum: ['folder', 'destroy']

- **`destination`** (`string`)
- **`order`** (`integer`) _(required, read-only)_
- **`created_at`** (`string`) _(required, read-only)_
- **`modified_at`** (`string`) _(required, read-only)_

#### `PATCH /as_email/api/v1/email_accounts/{email_account_pk}/message_filter_rules/{id}/`

**Operation:** `v1_email_accounts_message_filter_rules_partial_update`

**Parameters:**

- `email_account_pk` (path, required)
- `id` (path, required) — A unique integer value identifying this message filter rule.

**Request Body** (`application/json`):

- **`header`** (``)
- **`pattern`** (`string`)
- **`action`** (`string`) — \* `folder` - folder

* `destroy` - destroy Enum: ['folder', 'destroy']

- **`destination`** (`string`)

**Request Body** (`application/x-www-form-urlencoded`):

- **`header`** (``)
- **`pattern`** (`string`)
- **`action`** (`string`) — \* `folder` - folder

* `destroy` - destroy Enum: ['folder', 'destroy']

- **`destination`** (`string`)

**Request Body** (`multipart/form-data`):

- **`header`** (``)
- **`pattern`** (`string`)
- **`action`** (`string`) — \* `folder` - folder

* `destroy` - destroy Enum: ['folder', 'destroy']

- **`destination`** (`string`)

**Response 200:**

- **`url`** (`string`) _(required, read-only)_
- **`email_account`** (`string`) _(required, read-only)_
- **`header`** (``)
- **`pattern`** (`string`) _(required)_
- **`action`** (`string`) — \* `folder` - folder

* `destroy` - destroy Enum: ['folder', 'destroy']

- **`destination`** (`string`)
- **`order`** (`integer`) _(required, read-only)_
- **`created_at`** (`string`) _(required, read-only)_
- **`modified_at`** (`string`) _(required, read-only)_

#### `DELETE /as_email/api/v1/email_accounts/{email_account_pk}/message_filter_rules/{id}/`

**Operation:** `v1_email_accounts_message_filter_rules_destroy`

**Parameters:**

- `email_account_pk` (path, required)
- `id` (path, required) — A unique integer value identifying this message filter rule.

**Response 204:** No response body

#### `POST /as_email/api/v1/email_accounts/{email_account_pk}/message_filter_rules/{id}/move/`

**Operation:** `v1_email_accounts_message_filter_rules_move_create`

Process one of the move commands to change the ordering of message
filter rules.

**Parameters:**

- `email_account_pk` (path, required)
- `id` (path, required) — A unique integer value identifying this message filter rule.

**Request Body** (`application/json`):

- **`command`** (`string`) _(required)_ — \* `up` - up

* `down` - down
* `to` - to
* `bottom` - bottom
* `top` - top Enum: ['up', 'down', 'to', 'bottom', 'top']

- **`location`** (`integer`)

**Request Body** (`application/x-www-form-urlencoded`):

- **`command`** (`string`) _(required)_ — \* `up` - up

* `down` - down
* `to` - to
* `bottom` - bottom
* `top` - top Enum: ['up', 'down', 'to', 'bottom', 'top']

- **`location`** (`integer`)

**Request Body** (`multipart/form-data`):

- **`command`** (`string`) _(required)_ — \* `up` - up

* `down` - down
* `to` - to
* `bottom` - bottom
* `top` - top Enum: ['up', 'down', 'to', 'bottom', 'top']

- **`location`** (`integer`)

**Response 200:**

- **`status`** (`string`) _(required)_
- **`url`** (`string`) _(required)_
- **`order`** (`integer`) _(required)_

#### `GET /as_email/api/v1/email_accounts/{id}/`

**Operation:** `v1_email_accounts_retrieve`

The EmailAccount. This represents an email address active on a server.
A user may have multiple EmailAccounts.

NOTE: The EmailAccount can not be created or deleted via the REST API.

**Parameters:**

- `id` (path, required) — A unique integer value identifying this email account.

**Response 200:**

- **`pk`** (`integer`) _(required, read-only)_
- **`created_at`** (`string`) _(required, read-only)_
- **`deactivated`** (`boolean`) _(required, read-only)_ — If an account is deactivated it can still receive email. However it is no longer allowed to send email. Aliasing to other email accounts is allowed, but no forwarding to an email account not on on the system is allowed.
- **`deactivated_reason`** (`string`) _(required, read-only)_ — Reason for the account being deactivated
- **`email_address`** (`string`) _(required, read-only)_ — The email address that will receive emails on this server, and the address that will be used as a login to send emails. It must have the same domin name as the associated server
- **`enabled`** (`boolean`) _(required, read-only)_ — If an account is not enabled, email for this account will not be accepted. This is equivalent to the email account not existing.
- **`message_filter_rules`** (`string`) _(required, read-only)_
- **`modified_at`** (`string`) _(required, read-only)_
- **`num_bounces`** (`integer`) _(required, read-only)_ — Every time this email account sends an email and it results in a bounce this counter will increment. The mail provider does not allow excessive bounced email and this is a check to make sure that does not happen. An asynchronous task will go through all accounts that have a non-zero number of bounces and reduce them by 1 once a day. If you have more than the limit your account will be deactivated until it goes under the limit.
- **`owner`** (`string`) _(required, read-only)_
- **`server`** (`string`) _(required, read-only)_
- **`url`** (`string`) _(required, read-only)_

#### `PUT /as_email/api/v1/email_accounts/{id}/`

**Operation:** `v1_email_accounts_update`

The EmailAccount. This represents an email address active on a server.
A user may have multiple EmailAccounts.

NOTE: The EmailAccount can not be created or deleted via the REST API.

**Parameters:**

- `id` (path, required) — A unique integer value identifying this email account.

**Response 200:**

- **`pk`** (`integer`) _(required, read-only)_
- **`created_at`** (`string`) _(required, read-only)_
- **`deactivated`** (`boolean`) _(required, read-only)_ — If an account is deactivated it can still receive email. However it is no longer allowed to send email. Aliasing to other email accounts is allowed, but no forwarding to an email account not on on the system is allowed.
- **`deactivated_reason`** (`string`) _(required, read-only)_ — Reason for the account being deactivated
- **`email_address`** (`string`) _(required, read-only)_ — The email address that will receive emails on this server, and the address that will be used as a login to send emails. It must have the same domin name as the associated server
- **`enabled`** (`boolean`) _(required, read-only)_ — If an account is not enabled, email for this account will not be accepted. This is equivalent to the email account not existing.
- **`message_filter_rules`** (`string`) _(required, read-only)_
- **`modified_at`** (`string`) _(required, read-only)_
- **`num_bounces`** (`integer`) _(required, read-only)_ — Every time this email account sends an email and it results in a bounce this counter will increment. The mail provider does not allow excessive bounced email and this is a check to make sure that does not happen. An asynchronous task will go through all accounts that have a non-zero number of bounces and reduce them by 1 once a day. If you have more than the limit your account will be deactivated until it goes under the limit.
- **`owner`** (`string`) _(required, read-only)_
- **`server`** (`string`) _(required, read-only)_
- **`url`** (`string`) _(required, read-only)_

#### `PATCH /as_email/api/v1/email_accounts/{id}/`

**Operation:** `v1_email_accounts_partial_update`

The EmailAccount. This represents an email address active on a server.
A user may have multiple EmailAccounts.

NOTE: The EmailAccount can not be created or deleted via the REST API.

**Parameters:**

- `id` (path, required) — A unique integer value identifying this email account.

**Response 200:**

- **`pk`** (`integer`) _(required, read-only)_
- **`created_at`** (`string`) _(required, read-only)_
- **`deactivated`** (`boolean`) _(required, read-only)_ — If an account is deactivated it can still receive email. However it is no longer allowed to send email. Aliasing to other email accounts is allowed, but no forwarding to an email account not on on the system is allowed.
- **`deactivated_reason`** (`string`) _(required, read-only)_ — Reason for the account being deactivated
- **`email_address`** (`string`) _(required, read-only)_ — The email address that will receive emails on this server, and the address that will be used as a login to send emails. It must have the same domin name as the associated server
- **`enabled`** (`boolean`) _(required, read-only)_ — If an account is not enabled, email for this account will not be accepted. This is equivalent to the email account not existing.
- **`message_filter_rules`** (`string`) _(required, read-only)_
- **`modified_at`** (`string`) _(required, read-only)_
- **`num_bounces`** (`integer`) _(required, read-only)_ — Every time this email account sends an email and it results in a bounce this counter will increment. The mail provider does not allow excessive bounced email and this is a check to make sure that does not happen. An asynchronous task will go through all accounts that have a non-zero number of bounces and reduce them by 1 once a day. If you have more than the limit your account will be deactivated until it goes under the limit.
- **`owner`** (`string`) _(required, read-only)_
- **`server`** (`string`) _(required, read-only)_
- **`url`** (`string`) _(required, read-only)_

#### `POST /as_email/api/v1/email_accounts/{id}/set_password/`

**Operation:** `v1_email_accounts_set_password_create`

The EmailAccount. This represents an email address active on a server.
A user may have multiple EmailAccounts.

NOTE: The EmailAccount can not be created or deleted via the REST API.

**Parameters:**

- `id` (path, required) — A unique integer value identifying this email account.

**Request Body** (`application/json`):

- **`password`** (`string`) _(required)_

**Request Body** (`application/x-www-form-urlencoded`):

- **`password`** (`string`) _(required)_

**Request Body** (`multipart/form-data`):

- **`password`** (`string`) _(required)_

**Response 200:**

- **`status`** (`string`) _(required)_

## Schemas

### ActionEnum

- `folder` - folder
- `destroy` - destroy

### AliasToDelivery

Base serializer for DeliveryMethod. The `delivery_type` field exposes the
concrete subclass name so clients can distinguish LocalDelivery from
AliasToDelivery.

- **`url`** (`string`) _(required, read-only)_
- **`pk`** (`integer`) _(required, read-only)_
- **`delivery_type`** (`string`) _(required, read-only)_
- **`enabled`** (`boolean`) — When disabled, this delivery method is skipped during message delivery.
- **`created_at`** (`string`) _(required, read-only)_
- **`modified_at`** (`string`) _(required, read-only)_
- **`target_account`** (`string`) _(required)_ — The EmailAccount messages will be aliased to.

### AliasToDeliveryRequest

Base serializer for DeliveryMethod. The `delivery_type` field exposes the
concrete subclass name so clients can distinguish LocalDelivery from
AliasToDelivery.

- **`enabled`** (`boolean`) — When disabled, this delivery method is skipped during message delivery.
- **`target_account`** (`string`) _(required)_ — The EmailAccount messages will be aliased to.

### CommandEnum

- `up` - up
- `down` - down
- `to` - to
- `bottom` - bottom
- `top` - top

### DeliveryMethodPolymorphic

One of:

- `LocalDelivery`
- `AliasToDelivery`

### DeliveryMethodPolymorphicRequest

One of:

- `LocalDeliveryRequest`
- `AliasToDeliveryRequest`

### EmailAccount

- **`pk`** (`integer`) _(required, read-only)_
- **`created_at`** (`string`) _(required, read-only)_
- **`deactivated`** (`boolean`) _(required, read-only)_ — If an account is deactivated it can still receive email. However it is no longer allowed to send email. Aliasing to other email accounts is allowed, but no forwarding to an email account not on on the system is allowed.
- **`deactivated_reason`** (`string`) _(required, read-only)_ — Reason for the account being deactivated
- **`email_address`** (`string`) _(required, read-only)_ — The email address that will receive emails on this server, and the address that will be used as a login to send emails. It must have the same domin name as the associated server
- **`enabled`** (`boolean`) _(required, read-only)_ — If an account is not enabled, email for this account will not be accepted. This is equivalent to the email account not existing.
- **`message_filter_rules`** (`string`) _(required, read-only)_
- **`modified_at`** (`string`) _(required, read-only)_
- **`num_bounces`** (`integer`) _(required, read-only)_ — Every time this email account sends an email and it results in a bounce this counter will increment. The mail provider does not allow excessive bounced email and this is a check to make sure that does not happen. An asynchronous task will go through all accounts that have a non-zero number of bounces and reduce them by 1 once a day. If you have more than the limit your account will be deactivated until it goes under the limit.
- **`owner`** (`string`) _(required, read-only)_
- **`server`** (`string`) _(required, read-only)_
- **`url`** (`string`) _(required, read-only)_

### HeaderEnum

- `addr` - addr
- `*` - \*
- `bcc` - bcc
- `cc` - cc
- `default` - default
- `x-dspam-result` - x-dspam-result
- `from` - from
- `reply-to` - reply-to
- `source` - source
- `x-spam-score` - x-spam-score
- `x-spam-status` - x-spam-status
- `subject` - subject
- `to` - to

### LocalDelivery

Base serializer for DeliveryMethod. The `delivery_type` field exposes the
concrete subclass name so clients can distinguish LocalDelivery from
AliasToDelivery.

- **`url`** (`string`) _(required, read-only)_
- **`pk`** (`integer`) _(required, read-only)_
- **`delivery_type`** (`string`) _(required, read-only)_
- **`enabled`** (`boolean`) — When disabled, this delivery method is skipped during message delivery.
- **`created_at`** (`string`) _(required, read-only)_
- **`modified_at`** (`string`) _(required, read-only)_
- **`maildir_path`** (`string`) _(required, read-only)_ — Root folder for the local MH mailbox. Left blank it will be auto-filled from the account's email address when first saved.
- **`autofile_spam`** (`boolean`) — When enabled, messages above the spam score threshold are automatically filed in the spam delivery folder.
- **`spam_delivery_folder`** (`string`) — Folder to deliver spam into when autofile_spam is enabled.
- **`spam_score_threshold`** (`integer`) — Messages with an X-Spam-Score at or above this value are considered spam. 15 is a reasonable default.

### LocalDeliveryRequest

Base serializer for DeliveryMethod. The `delivery_type` field exposes the
concrete subclass name so clients can distinguish LocalDelivery from
AliasToDelivery.

- **`enabled`** (`boolean`) — When disabled, this delivery method is skipped during message delivery.
- **`autofile_spam`** (`boolean`) — When enabled, messages above the spam score threshold are automatically filed in the spam delivery folder.
- **`spam_delivery_folder`** (`string`) — Folder to deliver spam into when autofile_spam is enabled.
- **`spam_score_threshold`** (`integer`) — Messages with an X-Spam-Score at or above this value are considered spam. 15 is a reasonable default.

### MessageFilterRule

A type of `ModelSerializer` that uses hyperlinked relationships with compound keys instead
of primary key relationships. Specifically:

- A 'url' field is included instead of the 'id' field.
- Relationships to other instances are hyperlinks, instead of primary keys.

NOTE: this only works with DRF 3.1.0 and above.

- **`url`** (`string`) _(required, read-only)_
- **`email_account`** (`string`) _(required, read-only)_
- **`header`** (``)
- **`pattern`** (`string`) _(required)_
- **`action`** (`string`) — \* `folder` - folder

* `destroy` - destroy Enum: ['folder', 'destroy']

- **`destination`** (`string`)
- **`order`** (`integer`) _(required, read-only)_
- **`created_at`** (`string`) _(required, read-only)_
- **`modified_at`** (`string`) _(required, read-only)_

### MessageFilterRuleRequest

A type of `ModelSerializer` that uses hyperlinked relationships with compound keys instead
of primary key relationships. Specifically:

- A 'url' field is included instead of the 'id' field.
- Relationships to other instances are hyperlinks, instead of primary keys.

NOTE: this only works with DRF 3.1.0 and above.

- **`header`** (``)
- **`pattern`** (`string`) _(required)_
- **`action`** (`string`) — \* `folder` - folder

* `destroy` - destroy Enum: ['folder', 'destroy']

- **`destination`** (`string`)

### MoveOrderRequest

Models that use the "ordered" feature need to expose via the REST API
methods for changing their ordering. This is done via the "move" method
added to the REST API for that model which takes this serializer

- **`command`** (`string`) _(required)_ — \* `up` - up

* `down` - down
* `to` - to
* `bottom` - bottom
* `top` - top Enum: ['up', 'down', 'to', 'bottom', 'top']

- **`location`** (`integer`)

### MoveResponse

- **`status`** (`string`) _(required)_
- **`url`** (`string`) _(required)_
- **`order`** (`integer`) _(required)_

### PasswordRequest

Serializer for password change endpoint on the EmailAccount.

- **`password`** (`string`) _(required)_

### PatchedAliasToDeliveryRequest

Base serializer for DeliveryMethod. The `delivery_type` field exposes the
concrete subclass name so clients can distinguish LocalDelivery from
AliasToDelivery.

- **`enabled`** (`boolean`) — When disabled, this delivery method is skipped during message delivery.
- **`target_account`** (`string`) — The EmailAccount messages will be aliased to.

### PatchedDeliveryMethodPolymorphicRequest

One of:

- `PatchedLocalDeliveryRequest`
- `PatchedAliasToDeliveryRequest`

### PatchedLocalDeliveryRequest

Base serializer for DeliveryMethod. The `delivery_type` field exposes the
concrete subclass name so clients can distinguish LocalDelivery from
AliasToDelivery.

- **`enabled`** (`boolean`) — When disabled, this delivery method is skipped during message delivery.
- **`autofile_spam`** (`boolean`) — When enabled, messages above the spam score threshold are automatically filed in the spam delivery folder.
- **`spam_delivery_folder`** (`string`) — Folder to deliver spam into when autofile_spam is enabled.
- **`spam_score_threshold`** (`integer`) — Messages with an X-Spam-Score at or above this value are considered spam. 15 is a reasonable default.

### PatchedMessageFilterRuleRequest

A type of `ModelSerializer` that uses hyperlinked relationships with compound keys instead
of primary key relationships. Specifically:

- A 'url' field is included instead of the 'id' field.
- Relationships to other instances are hyperlinks, instead of primary keys.

NOTE: this only works with DRF 3.1.0 and above.

- **`header`** (``)
- **`pattern`** (`string`)
- **`action`** (`string`) — \* `folder` - folder

* `destroy` - destroy Enum: ['folder', 'destroy']

- **`destination`** (`string`)

### SetPasswordResponse

- **`status`** (`string`) _(required)_
