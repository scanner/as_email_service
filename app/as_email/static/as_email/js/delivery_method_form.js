// DeliveryMethodForm component
//
// Wraps a single DeliveryMethod object. Uses the registry to render the
// correct sub-form for the delivery type, and owns all API communication
// for that one delivery method: save (PATCH or POST), delete (DELETE), and
// the quick enabled-toggle (PATCH of just the `enabled` field).
//
import { ref, computed } from "vue";
import {
  DELIVERY_TYPE_COMPONENTS,
  DELIVERY_TYPE_ICONS,
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

    // DRF wraps every field error in an array even when there is only one
    // message. Flatten single-item arrays to plain strings for clean display.
    //
    // DRF wraps field errors in arrays. Join them into a single string for
    // clean display.
    //
    const flattenErrors = (body) => {
      if (!body || typeof body !== "object") return body;
      return Object.fromEntries(
        Object.entries(body).map(([k, v]) =>
          Array.isArray(v) ? [k, v.join(", ")] : [k, v],
        ),
      );
    };

    // View/edit mode for existing methods. New methods start in edit mode
    // immediately (they have no saved state to display).
    //
    const isEditing = ref(props.isNew);

    // Expand/collapse state: existing methods start collapsed; new methods
    // start expanded (they go straight into edit mode).
    //
    const isExpanded = ref(props.isNew);

    const toggleExpanded = () => {
      // Prevent collapsing while an edit is in progress.
      if (!isEditing.value) {
        isExpanded.value = !isExpanded.value;
      }
    };

    // One-line summary shown in the card header when the card is collapsed.
    //
    const deliverySummary = computed(() => {
      const d = formData.value;
      if (d.delivery_type === "LocalDelivery") {
        return d.autofile_spam
          ? `Spam → ${d.spam_delivery_folder}`
          : "No spam filing";
      }
      if (d.delivery_type === "AliasToDelivery") {
        return d.target_account || "(no target set)";
      }
      if (d.delivery_type === "ImapDelivery") {
        const host = d.imap_host || "?";
        const port = d.imap_port || 993;
        const user = d.username || "?";
        return `${host}:${port} (${user})`;
      }
      return "";
    });

    ////////////////////////////////////////////////////////////////////////
    //
    // Pick the right sub-form component and display info from the registry.
    //
    const subFormComponent = computed(
      () => DELIVERY_TYPE_COMPONENTS[props.deliveryMethod.delivery_type],
    );

    const deliveryTypeLabel = computed(
      () =>
        DELIVERY_TYPE_LABELS[props.deliveryMethod.delivery_type] ??
        props.deliveryMethod.delivery_type,
    );

    const deliveryTypeIcon = computed(
      () => DELIVERY_TYPE_ICONS[props.deliveryMethod.delivery_type] ?? "📬",
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
    // For ImapDelivery: if the password field contains a value (meaning the
    // user has typed a new password), run a connection test first and abort
    // with an error if it fails. This prevents saving credentials that are
    // known to be wrong.
    //
    const save = async () => {
      saving.value = true;
      errors.value = {};
      try {
        if (
          formData.value.delivery_type === "ImapDelivery" &&
          formData.value.password &&
          props.deliveryMethodsUrl
        ) {
          const testRes = await fetch(props.deliveryMethodsUrl + "test_imap/", {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              imap_host: formData.value.imap_host,
              imap_port: formData.value.imap_port,
              username: formData.value.username,
              password: formData.value.password,
            }),
          });
          if (!testRes.ok) {
            let errBody;
            try {
              errBody = await testRes.json();
            } catch {
              errBody = {};
            }
            errors.value = {
              detail: `Connection test failed: ${
                errBody.message ??
                errBody.detail ??
                "please verify your credentials."
              }`,
            };
            return;
          }
        }

        let res;
        const body = JSON.stringify(formData.value);
        if (props.isNew) {
          res = await fetch(props.deliveryMethodsUrl, {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body,
          });
        } else {
          res = await fetch(props.deliveryMethod.url, {
            method: "PATCH",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body,
          });
        }

        if (res.ok) {
          const data = await res.json();
          if (props.isNew) {
            ctx.emit("created", data);
          } else {
            isEditing.value = false;
            ctx.emit("saved", data);
          }
        } else {
          let errBody;
          try {
            errBody = await res.json();
          } catch {
            errBody = { detail: `HTTP ${res.status}: ${res.statusText}` };
          }
          errors.value = flattenErrors(errBody);
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
    // Enter / exit edit mode for existing methods.
    //
    const startEdit = () => {
      isExpanded.value = true;
      isEditing.value = true;
    };

    const cancelEdit = () => {
      formData.value = { ...props.deliveryMethod };
      errors.value = {};
      isEditing.value = false;
    };

    ////////////////////////////////////////////////////////////////////////
    //
    // Toggle enabled: immediately PATCHes just the `enabled` field.
    // Used by the clickable Enabled/Disabled tag in the card header.
    //
    const toggleEnabled = async () => {
      if (saving.value || deleting.value) return;
      saving.value = true;
      errors.value = {};
      try {
        const newEnabled = !formData.value.enabled;
        const res = await fetch(props.deliveryMethod.url, {
          method: "PATCH",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: newEnabled }),
        });
        if (res.ok) {
          const data = await res.json();
          formData.value = { ...formData.value, enabled: data.enabled };
          ctx.emit("saved", data);
        } else {
          let errBody;
          try {
            errBody = await res.json();
          } catch {
            errBody = { detail: `HTTP ${res.status}: ${res.statusText}` };
          }
          errors.value = flattenErrors(errBody);
        }
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
            errors.value = flattenErrors(await res.json());
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
      isEditing,
      isExpanded,
      subFormComponent,
      deliveryTypeLabel,
      deliveryTypeIcon,
      deliverySummary,
      save,
      startEdit,
      cancelEdit,
      toggleExpanded,
      toggleEnabled,
      destroy,
      onFieldUpdate,
    };
  },

  template: "#template-delivery-method-form",
};
