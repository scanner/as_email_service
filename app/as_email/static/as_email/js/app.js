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
    const emailAccountCards = bulmaCollapsible.attach(".is-collapsible");
  },
});
app.mount("#asemail-vue-app");
