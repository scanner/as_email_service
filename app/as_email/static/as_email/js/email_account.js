// Vue Component for an EmailAccount
//
import { ref } from "vue";
import MessageFilterRules from "./MessageFilterRules.js";
import DeliveryMethodList from "./delivery_method_list.js";

////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
//
export default {
  name: "EmailAccount",

  ////////////////////////////////////////////////////////////////////////////
  //
  props: {
    pk: {
      // NOTE: pk == primary key.. unique integer for this EmailAccount
      type: Number,
      required: true,
    },
    // When true the card starts expanded. Set by the parent when there is
    // only one account so the user lands directly in the detail view.
    //
    initialExpanded: { type: Boolean, default: false },
    url: {
      type: String,
      required: true,
    },
    emailAddress: {
      type: String,
      required: true,
    },
    // URL for the nested delivery_methods collection, e.g.:
    // /as_email/api/v1/email_accounts/1/delivery_methods/
    deliveryMethodsUrl: {
      type: String,
      required: true,
    },
    messageFilterRules: {
      type: String,
      default: "",
      required: true,
    },
    numBounces: {
      type: Number,
      default: 0,
      required: true,
    },
    deactivated: {
      type: Boolean,
      default: false,
      required: true,
    },
    deactivatedReason: {
      type: String,
      default: "",
      required: true,
    },
    // Server-rendered initial delivery method counts. These seed the header
    // badges immediately on page load; DeliveryMethodList updates them via
    // @counts-updated whenever the list is loaded or modified.
    //
    dmTotal: { type: Number, default: null },
    dmEnabled: { type: Number, default: null },
    validEmailAddresses: {
      type: Array,
      default: [],
      required: false,
    },
    fieldInfo: {
      type: Object,
      default: {},
      required: false,
    },
    setPasswordAction: {
      type: String,
      default: "set_password/",
      required: false,
    },
  },

  ////////////////////////////////////////////////////////////////////////////
  //
  components: {
    MessageFilterRules: MessageFilterRules,
    DeliveryMethodList: DeliveryMethodList,
  },

  ////////////////////////////////////////////////////////////////////////////
  //
  // Since we are using Django templating to render the actual HTML page
  // we need to use different delimeters for Vue.
  //
  delimiters: ["[[", "]]"],

  ////////////////////////////////////////////////////////////////////////////
  //
  setup(props) {
    // Card expand/collapse state — seeded from prop so single-account users
    // land with the card already open.
    //
    const isExpanded = ref(props.initialExpanded);

    // Badge counts — seeded from server-rendered data so they appear on the
    // collapsed card immediately. DeliveryMethodList updates them via
    // @counts-updated after any fetch, create, save, or delete.
    //
    const methodCount = ref(props.dmTotal);
    const enabledMethodCount = ref(props.dmEnabled);

    // Account Settings inline edit state.
    //
    const isEditingSettings = ref(false);
    const editPassword = ref("");
    const showEditPassword = ref(false);
    const settingsSaving = ref(false);
    const settingsError = ref("");

    // Error messages for deactivated / bounce warnings shown at the top of
    // the expanded card content.
    //
    const labelErrorMessages = ref({
      detail: "",
    });

    // Extract field help text for tooltips on the fields that remain at the
    // EmailAccount level (deactivated, num_bounces).
    //
    const labelTooltips = {};
    for (let [k, v] of Object.entries(props.fieldInfo)) {
      if ("help_text" in v) {
        labelTooltips[k] = v.help_text;
      }
    }

    // Passed to DeliveryMethodList → DeliveryMethodForm → AliasToDeliveryForm
    // for the target_account picker. We exclude the owning account's own
    // address to prevent self-aliasing.
    //
    const filteredValidEmailAddrs = props.validEmailAddresses.filter(
      (x) => x !== props.emailAddress,
    );

    ////////////////////////////////////////////////////////////////////////
    //
    // Invoked by the card header click to toggle expand/collapse.
    //
    const toggleExpanded = () => {
      isExpanded.value = !isExpanded.value;
    };

    ////////////////////////////////////////////////////////////////////////
    //
    // Called by DeliveryMethodList via @counts-updated when the list is
    // loaded or modified.
    //
    const onCountsUpdated = ({ total, enabled }) => {
      methodCount.value = total;
      enabledMethodCount.value = enabled;
    };

    ////////////////////////////////////////////////////////////////////////
    //
    // Check password strength using zxcvbn. Returns true if strong enough.
    // Updates the input element's CSS classes and settingsError.
    //
    const checkPasswordStrength = (inputEl) => {
      const result = zxcvbn(editPassword.value);
      if (result.score <= 2) {
        inputEl.classList.add("is-danger");
        inputEl.classList.remove("is-warning", "is-success");
        const suggestions = result.feedback.suggestions.join(", ");
        settingsError.value =
          result.feedback.warning.length > 0
            ? `${result.feedback.warning}: ${suggestions}`
            : suggestions;
        return false;
      }
      inputEl.classList.remove("is-danger");
      inputEl.classList.add(result.score === 3 ? "is-warning" : "is-success");
      inputEl.classList.remove(
        result.score === 3 ? "is-success" : "is-warning",
      );
      settingsError.value = "";
      return true;
    };

    ////////////////////////////////////////////////////////////////////////
    //
    // Save Account Settings: POST to set_password if a new password was entered.
    //
    const saveAccountSettings = async () => {
      settingsError.value = "";
      settingsSaving.value = true;
      try {
        if (editPassword.value) {
          const result = zxcvbn(editPassword.value);
          if (result.score <= 2) {
            const suggestions = result.feedback.suggestions.join(", ");
            settingsError.value =
              result.feedback.warning.length > 0
                ? `${result.feedback.warning}: ${suggestions}`
                : suggestions || "Password is too weak.";
            return;
          }
          const set_password_url = new URL(props.setPasswordAction, props.url);
          const res = await fetch(set_password_url.href, {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json; charset=UTF-8" },
            body: JSON.stringify({ password: editPassword.value }),
          });
          if (!res.ok) {
            if (res.status === 401 || res.status === 403) {
              settingsError.value = "Session expired — please reload the page.";
            } else {
              try {
                const err = await res.json();
                settingsError.value =
                  err.details || err.detail || `HTTP ${res.status}`;
              } catch {
                settingsError.value = `HTTP ${res.status}: ${res.statusText}`;
              }
            }
            return;
          }
        }

        isEditingSettings.value = false;
        editPassword.value = "";
        showEditPassword.value = false;
      } finally {
        settingsSaving.value = false;
      }
    };

    ////////////////////////////////////////////////////////////////////////
    //
    const cancelEditSettings = () => {
      isEditingSettings.value = false;
      editPassword.value = "";
      showEditPassword.value = false;
      settingsError.value = "";
    };

    //////////////////////////////////////////////////////////////////////
    //
    return {
      isExpanded,
      methodCount,
      enabledMethodCount,
      isEditingSettings,
      editPassword,
      showEditPassword,
      settingsSaving,
      settingsError,
      labelErrorMessages,
      labelTooltips,
      filteredValidEmailAddrs,
      toggleExpanded,
      onCountsUpdated,
      checkPasswordStrength,
      saveAccountSettings,
      cancelEditSettings,
      props,
    };
  },
  template: "#template-email-account",
};
