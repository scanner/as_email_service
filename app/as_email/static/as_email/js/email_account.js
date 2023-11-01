// Vue Component for an EmailAccount
//
import { ref } from "https://unpkg.com/vue@3/dist/vue.esm-browser.js";
import MessageFilterRule from './message_filter_rule.js';

const submitDisabled = ref(false);
const resetDisabled = ref(false);

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
        }
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

        ////////////////////////////////////////////////////////////////////////
        //
        const submitData = async function () {
            submitDisabled.value = true;
            try {
                let data = {
                    "delivery_method": props.deliveryMethod,
                    "autofile_spam": props.autofileSpam,
                    "spam_delivery_folder": props.spamDeliveryFolder,
                    "spam_score_threshold": props.spamSoreThreshold,
                    "alias_for": props.aliasFor,
                    "aliases": props.aliases,
                    "forward_to": props.forwardTo
                };

                console.log("Submitting data to " + props.url);
                console.log("Data: " + JSON.stringify(data,null,2));

                // If the data for aliases or aliasFor changed we need to emit
                // events upward to tell it the parent to refresh the aliases
                // for some EmailAccounts. We use the `aliasesChanged` event
                // for this.
                //
                let emailAccountsChanged = [];
                ctx.emit("aliasesChanged", emailAccountsChanged);
                // sleep for a bit so our submit button goes inactive for a
                // short bit.
                await new Promise(r => setTimeout(r, 2000));
            } finally {
                submitDisabled.value = false;
            }
        };

        ////////////////////////////////////////////////////////////////////////
        //
        const resetData = async function () {
            resetDisabled.value=true;
            try {
                let res = await fetch(props.url);
                if (res.ok) {
                    let data = await res.json();
                    console.log("Got data from server: " + JSON.stringify(data,null,2));
                    ctx.emit("update:deliveryMethod", data.delivery_method);
                    ctx.emit("update:autofileSpam", data.auto_file_spam);
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
                }
            } finally {
                resetDisabled.value = false;
            }
        };

        //////////
        //
        // setup code that does stuff
        //
        //////////
        console.log("Primary key: " + props.pk + " email address: " + props.emailAddress);

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
            props,
        };
    },
    template: '#template-email-account'
}
