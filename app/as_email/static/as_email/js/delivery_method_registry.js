// Delivery Method Registry
//
// Maps delivery_type strings to their Vue form components, display labels,
// icons, and default field values for new instances.
//
// To add a new delivery type (e.g. ImapDelivery):
//   1. Import its form component here
//   2. Add an entry to each of the four exports below
//   3. Nothing else needs to change
//
import LocalDeliveryForm from "./local_delivery_form.js";
import AliasToDeliveryForm from "./alias_to_delivery_form.js";
import ImapDeliveryForm from "./imap_delivery_form.js";

////////////////////////////////////////////////////////////////////////////
//
// Maps delivery_type → Vue component that renders the type-specific fields.
//
export const DELIVERY_TYPE_COMPONENTS = {
  LocalDelivery: LocalDeliveryForm,
  AliasToDelivery: AliasToDeliveryForm,
  ImapDelivery: ImapDeliveryForm,
};

////////////////////////////////////////////////////////////////////////////
//
// Human-readable labels for each delivery type, used in the UI.
//
export const DELIVERY_TYPE_LABELS = {
  LocalDelivery: "Local Delivery",
  AliasToDelivery: "Alias-To",
  ImapDelivery: "IMAP Delivery",
};

////////////////////////////////////////////////////////////////////////////
//
// Emoji icons for each delivery type, shown in the card header.
//
export const DELIVERY_TYPE_ICONS = {
  LocalDelivery: "📁",
  AliasToDelivery: "↪️",
  ImapDelivery: "📧",
};

////////////////////////////////////////////////////////////////////////////
//
// Default field values used when creating a new delivery method of a given
// type. The `delivery_type` field must be included so the backend knows which
// serialiser to use.
//
// These defaults also serve as the fallback for frontend-only fields that the
// API does not (yet) store or return. DeliveryMethodList.applyFrontendDefaults
// merges these over the API response so edit forms always have a complete
// starting state. Once the backend starts persisting and returning a field,
// the API value will automatically take precedence — no changes needed here.
//
// Fields currently frontend-only (not persisted by the backend):
//   ImapDelivery.auth_type — always "password" for now; when OAuth2 support
//     is added the backend will store and return the auth type, and this
//     default will be overridden automatically.
//
// Note: ImapDelivery.password is NOT listed here. The password is
//   intentionally never returned by the API (it is write-only, stored
//   encrypted). Its absence from the API response is by design, not a
//   gap to be filled with a default. See imap_delivery_form.js for how
//   the UI handles the always-empty password field.
//
export const DELIVERY_TYPE_DEFAULTS = {
  LocalDelivery: {
    delivery_type: "LocalDelivery",
    enabled: true,
    autofile_spam: true,
    spam_delivery_folder: "Spam",
    spam_score_threshold: 15,
  },
  AliasToDelivery: {
    delivery_type: "AliasToDelivery",
    enabled: true,
    target_account: "",
  },
  ImapDelivery: {
    delivery_type: "ImapDelivery",
    enabled: true,
    imap_host: "",
    imap_port: 993,
    // auth_type is frontend-only until OAuth2 is implemented. See note above.
    auth_type: "password",
    username: "",
    password: "",
    autofile_spam: true,
    spam_score_threshold: 5,
  },
};
