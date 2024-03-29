// AS Email App Vue/JS file
//
import { createApp, ref, reactive, onMounted } from "vue";
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
// This function is hooked to the event `aliasesChanged` from all of the
// EmailAccount components. It is called with a list of email addresses that
// have been added or removed as aliases/alias_fors. This function needs to
// query the REST API for the aliases for at least those email accounts and
// update the aliases in the reactive emailAccountsData object (which will
// automatically cause the subordinate EmailAccount components to update their
// presented information.)
//
async function updateAliases(emailAddresses) {
  if (emailAddresses.length == 0) {
    return;
  }

  // We have the list of email addresses that have been updated. We could
  // make one query for each, but instead we will just query the endpoint
  // that lists all of the EmailAccounts because:
  // 1) it is only one round trip to the server
  // 2) the amount of total data is really small.. so it is cheaper to do
  //    just this one call instead of several for smaller amounts.
  //
  // XXX we should consider installing `drf-flex-fields` in the server and only
  //     querying aliases/aliasFor (and only for the email accounts listed. But
  //     for now this brute force approach is good enough.
  //     see: https://sunscrapers.com/blog/the-ultimate-tutorial-for-django-rest-framework-selective-fields-and-related-objects-part-7/
  //
  let res = await fetch(initialData.email_account_list_url);
  if (!res.ok) {
    // XXX put up some sort of error notice on the main page
    //
    console.log(
      `Unable to get field data for EmailAccount: ${res.statusText}(${res.status})`,
    );
  }

  let emailAccounts = await res.json();
  // Loop through the email accounts and if the emailAccount.email_address is
  // in the list of email addresses, then update the reactive list of aliases
  // and aliasFor in emailAccountsData.
  //
  for (const emailAccount of emailAccounts) {
    if (emailAddresses.includes(emailAccount.email_address)) {
      // The key into the object of reactive email account data is the
      // primary key of the specific email account with `pk` prefixed.
      //
      // XXX This was done so we could dot notation for the `v-model`
      //     bindings in the index.html template
      //
      let key = "pk" + emailAccount.pk;
      emailAccountsData[key].aliases = emailAccount.aliases;
      emailAccountsData[key].alias_for = emailAccount.alias_for;
    }
  }
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
      updateAliases,
    };
  },
  delimiters: ["[[", "]]"],
  mounted() {
    // Hook up the 'bulma-collapsible' and bulma-tags-input support js code
    //
    const emailAccountCards = bulmaCollapsible.attach(".is-collapsible");
  },
});
app.mount("#asemail-vue-app");
