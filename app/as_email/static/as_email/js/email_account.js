// Vue Component for an EmailAccount
//
import { ref } from "https://unpkg.com/vue@3/dist/vue.esm-browser.js";
import MessageFilterRule from './message_filter_rule.js';

export default {
    props: [
        "alias_for",
        "aliases",
        "autofile_spam",
        "deactivated",
        "deactivated_reason",
        "delivery_method",
        "email_address",
        "num_bounces",
        "owner",
        "pk",
        "server",
        "spam_delivery_folder",
        "spam_score_threshold",
        "url",
    ],
    // An event sent to the parent component to indicate that aliases or
    // alias_for has changed in this component and other EmailAccount
    // components should have their aliases,alias_for's re-pulled from the
    // server because they may have changed.
    //
    emits: [ 'update-aliases' ],
    components: {
        MessageFilterRule: MessageFilterRule
    },
    setup(props, ctx) {
        // access props.alias_for, etc.
    },
    template: `
`
}
