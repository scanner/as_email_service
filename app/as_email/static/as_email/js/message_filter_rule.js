// Vue Component for a MessageFilterRule
//
import { ref } from "https://unpkg.com/vue@3/dist/vue.esm-browser.js";

export default {
    props: {
        header: String,
        pattern: String,
        action: String,
        destination: String,
        order: Number,
    },
    setup(props) {
        // access props.header, etc.
    },
    template: ``
}
