// Vue Component for a MessageFilterRule
//
import { ref } from "vue";

export default {
  props: {
    url: String,
  },
  setup(props) {
    // access props.header, etc.
    //////////////////////////////////////////////////////////////////////
    //
    // Return the public attributes and methods on the EmailAccount
    // component
    //
    //////////////////////////////////////////////////////////////////////
    return {
      props,
    };
  },
  template: "#template-message-filter-rules",
};
