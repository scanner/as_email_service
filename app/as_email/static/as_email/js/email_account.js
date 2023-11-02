// Vue Component for an EmailAccount
//
import { ref } from "https://unpkg.com/vue@3/dist/vue.esm-browser.js";
import MessageFilterRule from './message_filter_rule.js';

// Messages that appear next to fields (mostly for error messages) For
// keys/attributes we use the same strings that the server would send us so we
// can use those directly as keys into this object.
//
const labelErrorMessages = ref({
    detail: "",
    alias_for: "" ,
    aliases: "",
    autofile_spam: "",
    delivery_method: "",
    forward_to: "",
    spam_delivery_folder: "",
    spam_score_threshold: "",
});

////////////////////////////////////////////////////////////////////////////
//
// Compare two arrays, ignoring order of elements.
//
function array_equals(a,b) {
    const asorted = [...a].sort();
    const bsorted = [...b].sort();

    return asorted.every((v,i) => v === bsorted[i]);
}

////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
//
export default {
    name: "EmailAccount",

    ////////////////////////////////////////////////////////////////////////////
    //
    props: {
        pk: { // NOTE: pk == primary key.. unique integer for this EmailAccount
            type: Number,
            required: true,
        },
        url: {
            type: String,
            required: true
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
            required: true
        },
        spamDeliveryFolder: {
            type: String,
            default: "",
            required: true
        },
        spamScoreThreshold: {
            type: Number,
            default: 15,
            required: true
        },
        aliasFor: {
            type: Array,
            default: [],
            required: true
        },
        aliases: {
            type: Array,
            default: [],
            required: true
        },
        forwardTo: {
            type: [String, null],
            default: '',
            required: true
        },
        numBounces: {
            type: Number,
            default: 0,
            required: true
        },
        deactivated: {
            type: Boolean,
            default: false,
            required: true
        },
        deactivatedReason: {
            type: String,
            default: "",
            required: true
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
    emits: [ 'update:deliveryMethod',
             'update:autofileSpam',
             'update:spamDeliveryFolder',
             'update:spamScoreThreshold',
             'update:aliasFor',
             'update:aliases',
             'update:forwardTo',
             'update:numBounces',
             'update:deactivated',
             'update:deactivatedReason',
             'aliasesChanged',
           ],

    ////////////////////////////////////////////////////////////////////////////
    //
    components: {
        MessageFilterRule: MessageFilterRule
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
        filteredValidEmailAddrs.value = props.validEmailAddresses.filter(
            (x) => { return x != props.emailAddress; }
        );

        ////////////////////////////////////////////////////////////////////////
        //
        const selectMultiple = (event_name, event) => {
            let selected = Array.from(event.target.selectedOptions).map((x) => x.value);
            ctx.emit(event_name, selected);
        };

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

                // aliasFor and aliases may be a string instead of an array (I
                // can not figure out how to get vue to do this which it does
                // with v-model when using v-bind and v-on)
                //
                let aliases = Array.isArray(props.aliases)? props.aliases : [props.aliases];
                let aliasFor = Array.isArray(props.aliasFor)? props.aliasFor : [props.aliasFor];
                let data = {
                    "delivery_method": props.deliveryMethod,
                    "autofile_spam": props.autofileSpam,
                    "spam_delivery_folder": props.spamDeliveryFolder,
                    "spam_score_threshold": props.spamSoreThreshold,
                    "alias_for": aliasFor,
                    "aliases": aliases,
                    "forward_to": props.forwardTo
                };
                console.log("Submitting data to " + props.url);
                console.log("Data: " + JSON.stringify(data,null,2));

                let res = await fetch(props.url, {
                    method: 'PATCH',
                    body: JSON.stringify(data),
                    headers: {
                        'Content-type': 'application/json; charset=UTF-8',
                    },
                });
                if (res.ok) {
                    // Before we emit data updates, compared the props for
                    // aliase and aliasFor to see if they differ from the data
                    // we got back from the server. If they do then after we
                    // emit the other events we will need to emit a
                    // `aliasesChanged` update that tells the parent component
                    // to refresh the data from the server so that all the
                    // EmailAccount components update.
                    //
                    let aliasesChange = false;


                    // XXX We should have a visual indicator that the 'Apply'
                    //     worked, like flash a check mark that fades out after
                    //     short delay.
                    //
                    // XXX We should make this a function.. DRY and all.
                    //
                    let data = await res.json();
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
                    // XXX Should also emit aliasesChanged if aliaases are
                    //     different in our props from what we got from the
                    //     server.
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

                // If the data for aliases or aliasFor changed we need to emit
                // events upward to tell it the parent to refresh the aliases
                // for some EmailAccounts. We use the `aliasesChanged` event
                // for this.
                //
                let emailAccountsChanged = [];
                ctx.emit("aliasesChanged", emailAccountsChanged);

                // sleep for a bit so our button goes inactive for a
                // short bit.. mostly to prevent multiple slams on the button
                // in quick succession.
                //
                await new Promise(r => setTimeout(r, 750));
            } finally {
                submitDisabled.value = false;
            }
        };

        ////////////////////////////////////////////////////////////////////////
        //
        const resetData = async function () {
            resetDisabled.value=true;
            try {
                // On `Reset` clear any error messages that may be set.
                //
                for (let key in labelErrorMessages.value) {
                    labelErrorMessages.value[key] = "";
                }

                let res = await fetch(props.url);
                if (res.ok) {
                    let data = await res.json();
                    console.log("Got data from server: " + JSON.stringify(data,null,2));
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
                    console.log(`Unable to get field data for EmailAccount ${props.emailAddress}: ${res.statusText}(${res.status})`);
                    labelErrorMessages['detail'] = `HTTP: ${res.status}: ${res.statusText}`;
                }

                // sleep for a bit so our button goes inactive for a
                // short bit.. mostly to prevent multiple slams on the button
                // in quick succession.
                //
                await new Promise(r => setTimeout(r, 750));

            } finally {
                resetDisabled.value = false;
            }
        };

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
            selectMultiple,
            submitData,
            submitDisabled,
            resetData,
            resetDisabled,
            labelErrorMessages,
            filteredValidEmailAddrs,
            props
        };
    },
    template: '#template-email-account'
}
