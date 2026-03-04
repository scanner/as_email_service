// DeliveryMethodList component
//
// Manages the full list of DeliveryMethod objects for one EmailAccount.
// Fetches the list on mount, and handles add / delete lifecycle by updating
// its local array in response to events from child DeliveryMethodForm
// components.
//
// Emits `countsUpdated` whenever the total or enabled count changes so the
// parent EmailAccount can show badges in its collapsed header.
//
// Emits `deliveryMethodChanged` whenever a delivery method is created, saved
// (including enable/disable toggles), or deleted (but NOT on the initial
// load) so the parent can trigger a refresh of data on other accounts that
// may be affected — e.g. the `aliased_from` list on the target of an
// AliasToDelivery.
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

  emits: ["countsUpdated", "deliveryMethodChanged"],

  ////////////////////////////////////////////////////////////////////////////
  //
  setup(props, ctx) {
    const deliveryMethods = ref([]);
    const loading = ref(false);
    const error = ref("");

    // When non-null, a new (unsaved) delivery method of this type is being
    // added. Its form is rendered below the existing list.
    //
    const addingType = ref(null);
    const showAddMenu = ref(false);

    ////////////////////////////////////////////////////////////////////////
    //
    // Emit the current counts to the parent EmailAccount so it can update
    // its header badges. Called on every load and mutation; callers that
    // represent a mutation also emit `deliveryMethodChanged` immediately
    // after so the parent can refresh data on other affected accounts.
    //
    const emitCounts = () => {
      const total = deliveryMethods.value.length;
      const enabled = deliveryMethods.value.filter((dm) => dm.enabled).length;
      ctx.emit("countsUpdated", { total, enabled });
    };

    ////////////////////////////////////////////////////////////////////////
    //
    // Merge DELIVERY_TYPE_DEFAULTS under every object that arrives from the
    // API so frontend-only fields (e.g. ImapDelivery.auth_type) are always
    // present when the edit form opens. The API object is spread last so its
    // values always win: once the backend starts persisting and returning a
    // field, the default is silently overridden with no changes needed here.
    //
    const applyFrontendDefaults = (dm) => {
      const defaults = DELIVERY_TYPE_DEFAULTS[dm.delivery_type] ?? {};
      return { ...defaults, ...dm };
    };

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
          deliveryMethods.value = (await res.json()).map(applyFrontendDefaults);
          emitCounts();
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
      // For AliasToDelivery, collect both the old and new target accounts so
      // both cards update if the user pointed the alias at a different account.
      //
      const affected = new Set();
      if (updated.delivery_type === "AliasToDelivery") {
        const old = deliveryMethods.value.find((dm) => dm.pk === updated.pk);
        if (old?.target_account) affected.add(old.target_account);
        if (updated.target_account) affected.add(updated.target_account);
      }
      const idx = deliveryMethods.value.findIndex((dm) => dm.pk === updated.pk);
      if (idx !== -1) {
        deliveryMethods.value[idx] = updated;
      }
      emitCounts();
      if (affected.size > 0) {
        ctx.emit("deliveryMethodChanged", { affectedAccounts: [...affected] });
      }
    };

    ////////////////////////////////////////////////////////////////////////
    //
    // Called by DeliveryMethodForm when a DELETE succeeds.
    //
    const onDeliveryMethodDeleted = (pk) => {
      const dm = deliveryMethods.value.find((dm) => dm.pk === pk);
      deliveryMethods.value = deliveryMethods.value.filter(
        (dm) => dm.pk !== pk,
      );
      emitCounts();
      if (dm?.delivery_type === "AliasToDelivery" && dm.target_account) {
        ctx.emit("deliveryMethodChanged", {
          affectedAccounts: [dm.target_account],
        });
      }
    };

    ////////////////////////////////////////////////////////////////////////
    //
    // Called by the "add" form's DeliveryMethodForm when a POST succeeds.
    // Append the new object to the list and close the add form.
    //
    const onDeliveryMethodCreated = (created) => {
      deliveryMethods.value.push(created);
      addingType.value = null;
      emitCounts();
      if (
        created.delivery_type === "AliasToDelivery" &&
        created.target_account
      ) {
        ctx.emit("deliveryMethodChanged", {
          affectedAccounts: [created.target_account],
        });
      }
    };

    ////////////////////////////////////////////////////////////////////////
    //
    // Show the add form for the given delivery type.
    //
    const startAdd = (deliveryType) => {
      addingType.value = deliveryType;
      showAddMenu.value = false;
    };

    const cancelAdd = () => {
      addingType.value = null;
    };

    onMounted(fetchDeliveryMethods);

    return {
      deliveryMethods,
      loading,
      error,
      addingType,
      showAddMenu,
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
