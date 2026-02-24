// ImapDeliveryForm component — STUB
//
// Backend support for IMAP delivery does not exist yet. This file is a
// placeholder so the registry import resolves and the slot is reserved.
// Uncomment the entry in delivery_method_registry.js when the backend
// schema lands.
//
// Fields this form will need when implemented:
//   imap_host         (string)
//   imap_port         (integer, default 993)
//   auth_type         ("password" | "oauth2")
//   username          (string, visible when auth_type == "password")
//   password          (string, visible when auth_type == "password")
//   oauth2 flow       (TBD, visible when auth_type == "oauth2")
//
export default {
  name: "ImapDeliveryForm",
  delimiters: ["[[", "]]"],

  props: {
    formData: { type: Object, required: true },
    errors: { type: Object, default: () => ({}) },
  },

  emits: ["update:field"],

  setup(props, ctx) {
    const update = (field, value) => ctx.emit("update:field", field, value);
    return { update };
  },

  template: "#template-imap-delivery-form",
};
