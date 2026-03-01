// ImapDeliveryForm component
//
// Renders editable fields for an ImapDelivery delivery method.
// Does NOT talk to the API — it only emits field changes up to
// DeliveryMethodForm, which owns the save/delete logic.
//
// NOTE: ImapDelivery backend support is not yet implemented. This component
// is registered in the template but kept commented out in
// delivery_method_registry.js until the backend schema lands.
//
// Fields:
//   imap_host         (string)
//   imap_port         (integer, default 993)
//   auth_type         ("password" | "oauth2")
//   username          (string, visible when auth_type == "password")
//   password          (string, visible when auth_type == "password")
//   oauth2 flow       (visible when auth_type == "oauth2")
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
