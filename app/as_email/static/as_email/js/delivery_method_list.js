// DeliveryMethodList component
//
// Manages the full list of DeliveryMethod objects for one EmailAccount.
// Fetches the list on mount, and handles add / delete lifecycle by updating
// its local array in response to events from child DeliveryMethodForm
// components.
//
// NOTE: The description for GH-161 mentioned ordering delivery methods, but
// the backend never implemented it — DeliveryMethod does not extend
// OrderedModel and DeliveryMethodViewSet has no `move` action. Ordering
// controls are omitted until the backend supports them.
//
import { ref, computed, onMounted } from "vue";
import DeliveryMethodForm from "./delivery_method_form.js";
import {
  DELIVERY_TYPE_LABELS,
  DELIVERY_TYPE_DEFAULTS,
} from "./delivery_method_registry.js";

////////////////////////////////////////////////////////////////////////////
//
export default {
  name: "DeliveryMethodList",
  delimiters: ["[[", "]]"],

  components: { DeliveryMethodForm },

  props: {
    emailAccountPk: { type: Number, required: true },
    // URL for the nested delivery_methods collection, e.g.:
    // /as_email/api/v1/email_accounts/1/delivery_methods/
    deliveryMethodsUrl: { type: String, required: true },
    // Passed down to AliasToDeliveryForm for the target_account picker,
    // already filtered to exclude the owning account's address.
    validEmailAddresses: { type: Array, default: () => [] },
  },

  ////////////////////////////////////////////////////////////////////////////
  //
  setup(props) {
    const deliveryMethods = ref([]);
    const loading = ref(false);
    const error = ref("");

    // When non-null, a new (unsaved) delivery method of this type is being
    // added. Its form is rendered below the existing list.
    //
    const addingType = ref(null);

    ////////////////////////////////////////////////////////////////////////
    //
    // Fetch the list from the API.
    //
    const fetchDeliveryMethods = async () => {
      loading.value = true;
      error.value = "";
      try {
        const res = await fetch(props.deliveryMethodsUrl, {
          credentials: "same-origin",
        });
        if (res.ok) {
          deliveryMethods.value = await res.json();
        } else {
          error.value = `Failed to load delivery methods: ${res.status} ${res.statusText}`;
        }
      } finally {
        loading.value = false;
      }
    };

    ////////////////////////////////////////////////////////////////////////
    //
    // Whether a LocalDelivery already exists on this account. The backend
    // enforces max-one, so the "Add Local Mailbox" button is disabled when
    // this is true.
    //
    const hasLocalDelivery = computed(() =>
      deliveryMethods.value.some((dm) => dm.delivery_type === "LocalDelivery"),
    );

    ////////////////////////////////////////////////////////////////////////
    //
    // Called by DeliveryMethodForm when a PATCH save succeeds — replace the
    // stale item in the list with the fresh data from the server.
    //
    const onDeliveryMethodSaved = (updated) => {
      const idx = deliveryMethods.value.findIndex((dm) => dm.pk === updated.pk);
      if (idx !== -1) {
        deliveryMethods.value[idx] = updated;
      }
    };

    ////////////////////////////////////////////////////////////////////////
    //
    // Called by DeliveryMethodForm when a DELETE succeeds.
    //
    const onDeliveryMethodDeleted = (pk) => {
      deliveryMethods.value = deliveryMethods.value.filter(
        (dm) => dm.pk !== pk,
      );
    };

    ////////////////////////////////////////////////////////////////////////
    //
    // Called by the "add" form's DeliveryMethodForm when a POST succeeds.
    // Append the new object to the list and close the add form.
    //
    const onDeliveryMethodCreated = (created) => {
      deliveryMethods.value.push(created);
      addingType.value = null;
    };

    ////////////////////////////////////////////////////////////////////////
    //
    // Show the add form for the given delivery type.
    //
    const startAdd = (deliveryType) => {
      addingType.value = deliveryType;
    };

    const cancelAdd = () => {
      addingType.value = null;
    };

    ////////////////////////////////////////////////////////////////////////
    //
    onMounted(fetchDeliveryMethods);

    return {
      deliveryMethods,
      loading,
      error,
      addingType,
      hasLocalDelivery,
      DELIVERY_TYPE_LABELS,
      DELIVERY_TYPE_DEFAULTS,
      startAdd,
      cancelAdd,
      onDeliveryMethodSaved,
      onDeliveryMethodDeleted,
      onDeliveryMethodCreated,
    };
  },

  template: "#template-delivery-method-list",
};
