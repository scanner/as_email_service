// AS Email App Vue/JS file
//
import { createApp, reactive } from "vue";
import EmailAccount from "./email_account.js";

// Get the data that the as_email service filled the document with that
// contains information about all the EmailAccount's.
//
// It also contains the DRF `options` data for the EmailAccount object so we
// know what fields exist, what types they are, read only or not, and
// descriptions.
//
const initialData = JSON.parse(document.getElementById("vue-data").textContent);

//////////////////////////////////////////
//
// Global, loaded once Vue reference objects
//
const emailAccountsData = {};
for (let k in initialData.email_accounts_data) {
  emailAccountsData[k] = reactive(initialData.email_accounts_data[k]);
}

//////////////////////////////////////////////////////////////////////////////
//
// Root Vue app
//
const app = createApp({
  components: {
    EmailAccount,
  },
  setup() {
    return {
      emailAccountsData,
      initialData,
    };
  },
  delimiters: ["[[", "]]"],
  mounted() {
    // Hook up the 'bulma-collapsible' support js code
    //
    bulmaCollapsible.attach(".is-collapsible");

    // bulmaCollapsible.attach() captures scrollHeight synchronously, before
    // Vue's async delivery-method fetches complete, so the inline style.height
    // is too small.  Attach a MutationObserver to each collapsible so that
    // whenever Vue adds or removes child nodes (fetched delivery methods, add
    // form, deleted form), the height is re-measured and corrected.
    //
    // MutationObserver fires as a microtask AFTER Vue's synchronous DOM patch
    // for a given render completes.  This is the correct moment: the deleted
    // (or added) nodes are already in their final state.  Vue watchers with
    // flush:'post', nextTick(), and setTimeout(fn,0) all fired too early in
    // testing — the deleted form's DOM was still present when we measured.
    //
    // We clear style.height before measuring so that scrollHeight reflects
    // the true content height rather than max(element height, content height).
    // The two assignments are batched by the browser (no visible flash); the
    // CSS transition on .is-collapsible then animates the size change.
    //
    document.querySelectorAll(".is-collapsible").forEach((col) => {
      new MutationObserver(() => {
        if (
          !col.style.height ||
          col.style.height === "0" ||
          col.style.height === "0px"
        ) {
          return;
        }
        // Read offsetHeight on the inner content element rather than using
        // scrollHeight on the collapsible itself.  When col.style.height is
        // cleared, the CSS rule "height: 0; overflow-y: hidden" takes effect
        // and browsers return 0 for scrollHeight on a height-0 overflow-hidden
        // element.  The inner element is not height-constrained by the parent's
        // overflow, so its offsetHeight always reflects the true content height.
        const inner = col.firstElementChild;
        if (inner) {
          col.style.height = inner.offsetHeight + "px";
        }
      }).observe(col, { subtree: true, childList: true });
    });
  },
});
app.mount("#asemail-vue-app");
