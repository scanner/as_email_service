// DeliveryMethodForm component
//
// Wraps a single DeliveryMethod object. Uses the registry to render the
// correct sub-form for the delivery type, and owns all API communication
// for that one delivery method: save (PATCH or POST) and delete (DELETE).
//
import { ref, computed } from "vue";
import {
  DELIVERY_TYPE_COMPONENTS,
  DELIVERY_TYPE_LABELS,
} from "./delivery_method_registry.js";

////////////////////////////////////////////////////////////////////////////
//
export default {
  name: "DeliveryMethodForm",
  delimiters: ["[[", "]]"],

  components: Object.fromEntries(
    Object.entries(DELIVERY_TYPE_COMPONENTS).map(([k, v]) => [v.name, v]),
  ),

  props: {
    // The full delivery method object from the API (has .url, .pk,
    // .delivery_type, and type-specific fields).
    deliveryMethod: { type: Object, required: true },
    // Set true when this form represents a new (unsaved) delivery method.
    // In that case save() does a POST to deliveryMethodsUrl instead of a
    // PATCH to deliveryMethod.url.
    isNew: { type: Boolean, default: false },
    // Required when isNew — the collection URL to POST to.
    deliveryMethodsUrl: { type: String, default: "" },
    // List of valid email addresses passed down to AliasToDeliveryForm.
    validEmailAddresses: { type: Array, default: () => [] },
  },

  emits: ["saved", "deleted", "created", "cancel"],

  ////////////////////////////////////////////////////////////////////////////
  //
  setup(props, ctx) {
    // Local editable copy — keeps in-progress changes isolated from the
    // parent's reactive data until the user clicks Save.
    //
    const formData = ref({ ...props.deliveryMethod });
    const saving = ref(false);
    const deleting = ref(false);
    const errors = ref({});

    ////////////////////////////////////////////////////////////////////////
    //
    // Pick the right sub-form component from the registry.
    //
    const subFormComponent = computed(
      () => DELIVERY_TYPE_COMPONENTS[props.deliveryMethod.delivery_type],
    );

    const deliveryTypeLabel = computed(
      () =>
        DELIVERY_TYPE_LABELS[props.deliveryMethod.delivery_type] ??
        props.deliveryMethod.delivery_type,
    );

    ////////////////////////////////////////////////////////////////////////
    //
    // Called by the sub-form when a field value changes.
    //
    const onFieldUpdate = (field, value) => {
      formData.value = { ...formData.value, [field]: value };
    };

    ////////////////////////////////////////////////////////////////////////
    //
    // Save: POST for new, PATCH for existing.
    //
    // NOTE: delivery_type is included in formData (spread from the prop) but
    // the backend does not require it on PATCH — it resolves the serializer
    // from the DB using the pk. It is harmless to send it.
    //
    const save = async () => {
      saving.value = true;
      errors.value = {};
      try {
        let res;
        if (props.isNew) {
          res = await fetch(props.deliveryMethodsUrl, {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(formData.value),
          });
        } else {
          res = await fetch(props.deliveryMethod.url, {
            method: "PATCH",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(formData.value),
          });
        }

        if (res.ok) {
          const data = await res.json();
          if (props.isNew) {
            ctx.emit("created", data);
          } else {
            ctx.emit("saved", data);
          }
        } else {
          // Try to parse a JSON error body; fall back to a plain status string
          // if the server returns no body (e.g. 500).
          //
          try {
            errors.value = await res.json();
          } catch {
            errors.value = { detail: `HTTP ${res.status}: ${res.statusText}` };
          }
          if (res.status === 401 || res.status === 403) {
            errors.value = {
              detail: "Session expired — please reload the page.",
            };
          }
        }

        // Brief debounce so the button does not get hammered on double-click.
        //
        await new Promise((r) => setTimeout(r, 750));
      } finally {
        saving.value = false;
      }
    };

    ////////////////////////////////////////////////////////////////////////
    //
    // Delete: ask for confirmation, then DELETE to the object's own URL.
    //
    const destroy = async () => {
      const label = deliveryTypeLabel.value;
      if (!confirm(`Delete this ${label} delivery method?`)) return;

      deleting.value = true;
      errors.value = {};
      try {
        const res = await fetch(props.deliveryMethod.url, {
          method: "DELETE",
          credentials: "same-origin",
        });

        // 204 No Content is the normal success response for DELETE.
        //
        if (res.ok || res.status === 204) {
          ctx.emit("deleted", props.deliveryMethod.pk);
        } else {
          try {
            errors.value = await res.json();
          } catch {
            errors.value = {
              detail: `Delete failed: HTTP ${res.status}: ${res.statusText}`,
            };
          }
          if (res.status === 401 || res.status === 403) {
            errors.value = {
              detail: "Session expired — please reload the page.",
            };
          }
        }
      } finally {
        deleting.value = false;
      }
    };

    ////////////////////////////////////////////////////////////////////////
    //
    return {
      formData,
      saving,
      deleting,
      errors,
      subFormComponent,
      deliveryTypeLabel,
      save,
      destroy,
      onFieldUpdate,
    };
  },

  template: "#template-delivery-method-form",
};
