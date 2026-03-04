// ImapDeliveryForm component
//
// Renders editable fields for an ImapDelivery delivery method.
// Does NOT talk to the API — it only emits field changes up to
// DeliveryMethodForm, which owns the save/delete logic.
//
// Fields:
//   imap_host             (string)
//   imap_port             (integer, default 993)
//   auth_type             ("password" | "oauth2"; oauth2 is a future placeholder)
//   username              (string, visible when auth_type == "password")
//   password              (string, visible when auth_type == "password")
//   autofile_spam         (boolean)
//   spam_score_threshold  (integer, visible when autofile_spam is true)
//
import { computed } from "vue";

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

    const isPasswordAuth = computed(
      () => props.formData.auth_type === "password",
    );
    const isOAuthAuth = computed(() => props.formData.auth_type === "oauth2");

    return { update, isPasswordAuth, isOAuthAuth };
  },

  template: "#template-imap-delivery-form",
};
