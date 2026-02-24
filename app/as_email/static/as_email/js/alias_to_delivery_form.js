// AliasToDeliveryForm component
//
// Renders editable fields for an AliasToDelivery delivery method.
// Does NOT talk to the API — it only emits field changes up to
// DeliveryMethodForm, which owns the save/delete logic.
//
import { computed } from "vue";
import VueSelect from "vue-select";

export default {
  name: "AliasToDeliveryForm",
  delimiters: ["[[", "]]"],

  components: {
    "v-select": VueSelect,
  },

  props: {
    formData: { type: Object, required: true },
    errors: { type: Object, default: () => ({}) },
    // List of valid email addresses for the target_account picker,
    // excluding the owning account's own address.
    validEmailAddresses: { type: Array, default: () => [] },
  },

  emits: ["update:field"],

  setup(props, ctx) {
    const update = (field, value) => ctx.emit("update:field", field, value);

    // v-select requires a writable computed so changes propagate back up
    // without mutating the prop directly.
    //
    const targetAccount = computed({
      get: () => props.formData.target_account,
      set: (value) => ctx.emit("update:field", "target_account", value),
    });

    return { update, targetAccount };
  },

  template: "#template-alias-to-delivery-form",
};
