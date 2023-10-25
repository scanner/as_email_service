// Vue Component for an EmailAccount
//
import { ref } from "https://unpkg.com/vue@3/dist/vue.esm-browser.js";

export default {
    props: [
        'alias_for',
        'aliases',
        'autofile_spam',
        'deactivated',
        'deactivated_reason',
        'delivery_method',
        'email_address',
        'num_bounces',
        'owner',
        'pk',
        'server',
        'spam_delivery_folder',
        'spam_score_threshold',
        'url'
    ],
    setup(props) {
        // access props.emailAccountData
    }
}
