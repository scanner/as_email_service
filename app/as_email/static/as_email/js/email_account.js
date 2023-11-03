// Vue Component for an EmailAccount
//
import { ref, computed } from "vue";
import VueSelect from "vue-select";
import MessageFilterRule from "./message_filter_rule.js";

////////////////////////////////////////////////////////////////////////////
//
// Return the difference (ie: changes) between two arrays.  We want the list of
// elements that have been added or removed from a compared to b.
//
// See: https://stackoverflow.com/questions/1187518/how-to-get-the-difference-between-two-arrays-in-javascript/3476612#3476612
//
function arrayDiff(a, b) {
  return [
    ...a.filter((x) => !b.includes(x)),
    ...b.filter((x) => !a.includes(x)),
  ];
}

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
    deliveryMethod: {
      type: String,
      default: "LD",
      required: true,
    },
    autofileSpam: {
      type: Boolean,
      default: true,
      required: true,
    },
    spamDeliveryFolder: {
      type: String,
      default: "",
      required: true,
    },
    spamScoreThreshold: {
      type: Number,
      default: 15,
      required: true,
    },
    aliasFor: {
      type: Array,
      default: [],
      required: true,
    },
    aliases: {
      type: Array,
      default: [],
      required: true,
    },
    forwardTo: {
      type: [String, null],
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
  },

  ////////////////////////////////////////////////////////////////////////////
  //
  // This is the subset of props that when they change we need to emit an
  // event that lets the parent know the values of these have changed.
  //
  emits: [
    "update:deliveryMethod",
    "update:autofileSpam",
    "update:spamDeliveryFolder",
    "update:spamScoreThreshold",
    "update:aliasFor",
    "update:aliases",
    "update:forwardTo",
    "update:numBounces",
    "update:deactivated",
    "update:deactivatedReason",
    "aliasesChanged",
  ],

  ////////////////////////////////////////////////////////////////////////////
  //
  components: {
    MessageFilterRule: MessageFilterRule,
    "v-select": VueSelect,
  },

  ////////////////////////////////////////////////////////////////////////////
  //
  // Since we are using Django templating to render the actual HTML page
  // we need to use different delimeters for Vue.
  //
  delimiters: ["[[", "]]"],

  ////////////////////////////////////////////////////////////////////////////
  //
  setup(props, ctx) {
    const submitDisabled = ref(false);
    const resetDisabled = ref(false);
    const filteredValidEmailAddrs = ref([]);

    // We fill up "filteredValidEmailAddrs" because the list of valid email
    // addresses is used for "aliasFor" and "aliases" and you are not
    // allowed to alias for yourself, so just to prevent confusion we
    // remove our own email address from the list of valid email addresse.
    //
    filteredValidEmailAddrs.value = props.validEmailAddresses.filter((x) => {
      return x != props.emailAddress;
    });

    //////////
    //
    // computed items
    //
    //////////

    ////////////////////////////////////////////////////////////////////////
    //
    // aliasFor and aliases are passed in to a v-select component, but are
    // given data that came in as a prop. We need to make sure that changes
    // to the prop are passed into the v-select and that changes to the
    // selected options in the v-select are passed back up to our parent
    // via update events. We do this by having a read/write computed item
    // that handles this translation.
    //
    const computedAliasFor = computed({
      get: () => props.aliasFor,
      set: (value) => ctx.emit("update:aliasFor", value),
    });
    const computedAliases = computed({
      get: () => props.aliases,
      set: (value) => ctx.emit("update:aliases", value),
    });

    //////////
    //
    // public methods
    //
    //////////

    ////////////////////////////////////////////////////////////////////////
    //
    const submitData = async function () {
      submitDisabled.value = true;
      try {
        // On `Apply` clear any error messages that may be set.
        //
        for (let key in labelErrorMessages.value) {
          labelErrorMessages.value[key] = "";
        }

        let data = {
          delivery_method: props.deliveryMethod,
          autofile_spam: props.autofileSpam,
          spam_delivery_folder: props.spamDeliveryFolder,
          spam_score_threshold: props.spamSoreThreshold,
          alias_for: props.aliasFor,
          aliases: props.aliases,
          forward_to: props.forwardTo,
        };
        console.log("Submitting data to " + props.url);
        console.log("Data: " + JSON.stringify(data, null, 2));

        let res = await fetch(props.url, {
          method: "PATCH",
          body: JSON.stringify(data),
          headers: {
            "Content-type": "application/json; charset=UTF-8",
          },
        });
        if (res.ok) {
          // XXX We should have a visual indicator that the 'Apply'
          //     worked, like flash a check mark that fades out after
          //     short delay.
          //
          // XXX We should make this a function.. DRY and all.
          //
          let data = await res.json();

          // Before we emit data updates, compared the props for
          // aliase and aliasFor to see if they differ from the data
          // we got back from the server. If they do then after we
          // emit the other events we will need to emit a
          // `aliasesChanged` update that tells the parent component
          // to refresh the data from the server so that all the
          // EmailAccount components update.
          //
          let aliasesDiffs = arrayDiff(props.aliases, data.aliases);
          let aliasForDiffs = arrayDiff(props.aliasFor, data.alias_for);
          let aliasChanges = [...new Set(aliasesDiffs.concat(aliasForDiffs))];
          console.log(`post patch, aliasesDiffs: ${aliasesDiffs}`);
          console.log(`post patch, aliasForDiffs: ${aliasForDiffs}`);
          console.log(`post patch, aliasChanges: ${aliasChanges}`);

          ctx.emit("update:deliveryMethod", data.delivery_method);
          ctx.emit("update:autofileSpam", data.autofile_spam);
          ctx.emit("update:spamDeliveryFolder", data.spam_delivery_folder);
          ctx.emit("update:spamScoreThreshold", data.spam_score_threshold);
          ctx.emit("update:aliasFor", data.alias_for);
          ctx.emit("update:aliases", data.aliases);
          ctx.emit("update:forwardTo", data.forward_to);
          ctx.emit("update:numBounces", data.num_bounces);
          ctx.emit("update:deactivated", data.deactivated);
          ctx.emit("update:deactivatedReason", data.deactivated_reason);

          // If aliases or aliasFor contents have changed update our parent
          // with the affected email addresses
          //
          if (aliasChanges.length != 0) {
            console.log(`alias changes: ${aliasChanges}`);
            ctx.emit("aliasesChanged", aliasChanges);
          }
        } else {
          // If the PATCH failed we should get back a JSON body which
          // has for its keys the fields that had a problem, and the
          // value is the error for that field.
          //
          // XXX we should catch failures that do not return json
          //     (like server is down)
          //
          let errors = await res.json();
          for (let label in errors) {
            labelErrorMessages.value[label] = errors[label];
          }
        }

        // sleep for a bit so our button goes inactive for a
        // short bit.. mostly to prevent multiple slams on the button
        // in quick succession.
        //
        await new Promise((r) => setTimeout(r, 750));
      } finally {
        submitDisabled.value = false;
      }
    };

    ////////////////////////////////////////////////////////////////////////
    //
    const resetData = async function () {
      resetDisabled.value = true;
      try {
        // On `Reset` clear any error messages that may be set.
        //
        for (let key in labelErrorMessages.value) {
          labelErrorMessages.value[key] = "";
        }

        let res = await fetch(props.url);
        if (res.ok) {
          let data = await res.json();
          console.log("Got data from server: " + JSON.stringify(data, null, 2));
          ctx.emit("update:deliveryMethod", data.delivery_method);
          ctx.emit("update:autofileSpam", data.autofile_spam);
          ctx.emit("update:spamDeliveryFolder", data.spam_delivery_folder);
          ctx.emit("update:spamScoreThreshold", data.spam_score_threshold);
          ctx.emit("update:aliasFor", data.alias_for);
          ctx.emit("update:aliases", data.aliases);
          ctx.emit("update:forwardTo", data.forward_to);
          ctx.emit("update:numBounces", data.num_bounces);
          ctx.emit("update:deactivated", data.deactivated);
          ctx.emit("update:deactivatedReason", data.deactivated_reason);
        } else {
          console.log(
            `Unable to get field data for EmailAccount ${props.emailAddress}: ${res.statusText}(${res.status})`,
          );
          labelErrorMessages[
            "detail"
          ] = `HTTP: ${res.status}: ${res.statusText}`;
        }

        // sleep for a bit so our button goes inactive for a
        // short bit.. mostly to prevent multiple slams on the button
        // in quick succession.
        //
        await new Promise((r) => setTimeout(r, 750));
      } finally {
        resetDisabled.value = false;
      }
    };

    // Messages that appear next to fields (mostly for error messages) For
    // keys/attributes we use the same strings that the server would send us so we
    // can use those directly as keys into this object.
    //
    const labelErrorMessages = ref({
      detail: "",
      alias_for: "",
      aliases: "",
      autofile_spam: "",
      delivery_method: "",
      forward_to: "",
      spam_delivery_folder: "",
      spam_score_threshold: "",
    });

    //////////
    //
    // setup code that does stuff goes here (as opposed to variable
    // declarations, initialization, and functions we are exporting.)
    //
    //////////

    //////////////////////////////////////////////////////////////////////
    //
    // Return the public attributes and methods on the EmailAccount
    // component
    //
    //////////////////////////////////////////////////////////////////////
    return {
      submitData,
      submitDisabled,
      resetData,
      resetDisabled,
      labelErrorMessages,
      filteredValidEmailAddrs,
      computedAliasFor,
      computedAliases,
      props,
    };
  },
  template: "#template-email-account",
};
