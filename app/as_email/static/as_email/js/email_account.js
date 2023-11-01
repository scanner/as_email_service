// Vue Component for an EmailAccount
//
import { ref } from "https://unpkg.com/vue@3/dist/vue.esm-browser.js";
import MessageFilterRule from './message_filter_rule.js';

export default {
    name: "EmailAccount",
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
            required: false
        },
        validEmailAddresses: {
            type: Array,
            default: [],
            required: false,
        }
    },
    // This is the subset of props that when they change we need to emit an
    // event that lets the parent know the values of these have changed.
    //
    emits: [ 'update:deliveryMethod',
             'update:autofileSpam',
             'update:spamDeliveryFolder',
             'update:spamScoreThredshold',
             'update:aliasFor',
             'update:aliases',
             'update:forwardTo'
           ],
    components: {
        MessageFilterRule: MessageFilterRule
    },

    // Since we are using Django templating to render the actual HTML page
    // we need to use different delimeters for Vue.
    //
    delimiters: ["[[", "]]"],
    setup(props, ctx) {
        // access props.alias_for, etc.
        const submitData = function () {
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
            console.log("Data: " + JSON.stringify(data));
        };

        // const url = props.url;
        console.log("Primary key: " + props.pk + " email address: " + props.emailAddress);

        return {
            submitData,
            props,
        };
    },
    template: '#template-email-account'
}
