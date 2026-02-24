// LocalDeliveryForm component
//
// Renders editable fields for a LocalDelivery delivery method.
// Does NOT talk to the API — it only emits field changes up to
// DeliveryMethodForm, which owns the save/delete logic.
//
export default {
  name: "LocalDeliveryForm",
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

  template: "#template-local-delivery-form",
};
