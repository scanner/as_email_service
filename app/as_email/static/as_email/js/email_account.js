// Vue Component for an EmailAccount
//
import { ref } from "https://unpkg.com/vue@3/dist/vue.esm-browser.js";
import MessageFilterRule from './message_filter_rule.js';

export default {
    name: "EmailAccount",
    props: {
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
    delimiters: ["[[", "]]"],
    setup(props, ctx) {
        // access props.alias_for, etc.
        console.log("Props: " + props.forwardTo);

        // The object we return from `setup()` is all the public methods and
        // data properties of the EmailAccount component
        //
        return {
        };
    },
    template: '#template-email-account'
}
