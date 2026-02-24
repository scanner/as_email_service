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
    const emailAccountPassword = ref("");
    const emailAccountPasswordConfirm = ref("");
    const emailAccountPasswordStatus = ref("");

    // Error messages for the password modal only. Delivery method field errors
    // are handled inside DeliveryMethodForm.
    //
    const labelErrorMessages = ref({
      detail: "",
      set_password: "",
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
    // Check to see if the password is strong enough to let the user use it. It
    // is used on key up to highlight the password field if it is or is not
    // good enough. It also is used by the setPassword method to make sure that
    // the password is good enough before posting it to the server.
    //
    const checkPassword = function (target) {
      const result = zxcvbn(emailAccountPassword.value);

      if (result.score <= 2) {
        target.classList.add("is-danger");
        target.classList.remove("is-warning", "is-success");

        let suggestions = result.feedback.suggestions.join(", ");
        let feedback =
          result.feedback.warning.length > 0
            ? `${result.feedback.warning}: ${suggestions}`
            : suggestions;

        labelErrorMessages.value["set_password"] = feedback;
      } else {
        // If the score is above 3 there will be no result.feedback. We check
        // if the confirm password is the same or not at this point.
        //
        if (emailAccountPassword.value != emailAccountPasswordConfirm.value) {
          labelErrorMessages.value["set_password"] =
            "Password and Confirm password do not match.";
          target.classList.add("is-danger");
          target.classList.remove("is-warning", "is-success");
          return;
        }

        target.classList.remove("is-danger");
        if (result.score == 3) {
          target.classList.remove("is-success");
          target.classList.add("is-warning");
        } else {
          target.classList.remove("is-warning");
          target.classList.add("is-success");
        }
        labelErrorMessages.value["set_password"] = "";
      }
    };

    ////////////////////////////////////////////////////////////////////////
    //
    const setPassword = async function ($event) {
      const modal = $event.target.dataset.target;
      const $target = document.getElementById(modal);
      const set_password_url = new URL(props.setPasswordAction, props.url);
      const result = zxcvbn(emailAccountPassword.value);

      // Disable the button while we are checking values and talking to the
      // server.
      //
      $event.target.setAttribute("disabled", true);

      // If the score is 2 or less then idle for a bit, re-enable the set
      // password button, and return. Do not even bother trying to set the
      // password.
      //
      if (result.score <= 2) {
        await new Promise((r) => setTimeout(r, 1500));
        $event.target.removeAttribute("disabled");
        return;
      }

      labelErrorMessages.value["set_password"] = "";

      try {
        emailAccountPasswordStatus.value = "Setting...";

        if (emailAccountPassword.value != emailAccountPasswordConfirm.value) {
          labelErrorMessages.value["set_password"] =
            "Password and Confirm password do not match.";
          return;
        }

        let res = await fetch(set_password_url.href, {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json; charset=UTF-8" },
          body: JSON.stringify({ password: emailAccountPassword.value }),
        });

        if (res.ok) {
          if ($target) {
            emailAccountPasswordStatus.value = "Password set successfully";
            // Sleep for a bit so our button goes inactive for a short
            // bit.. mostly to prevent multiple slams on the button in quick
            // succession.
            //
            await new Promise((r) => setTimeout(r, 1500));
            $target.classList.remove("is-active");
          }
        } else {
          emailAccountPasswordStatus.value = "";
          if (res.status === 401 || res.status === 403) {
            labelErrorMessages.value["set_password"] =
              "Session expired — please reload the page.";
          } else {
            try {
              let errors = await res.json();
              labelErrorMessages.value["set_password"] = errors["details"];
            } catch {
              labelErrorMessages.value["set_password"] =
                `HTTP ${res.status}: ${res.statusText}`;
            }
          }
          await new Promise((r) => setTimeout(r, 750));
        }
      } finally {
        emailAccountPasswordStatus.value = "";
        $event.target.removeAttribute("disabled");
      }
    };

    //////////////////////////////////////////////////////////////////////
    //
    // Return the public attributes and methods on the EmailAccount component.
    //
    //////////////////////////////////////////////////////////////////////
    return {
      labelErrorMessages,
      labelTooltips,
      filteredValidEmailAddrs,
      emailAccountPassword,
      emailAccountPasswordConfirm,
      emailAccountPasswordStatus,
      checkPassword,
      setPassword,
      props,
    };
  },
  template: "#template-email-account",
};
