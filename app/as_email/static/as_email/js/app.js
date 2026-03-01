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
// Fetch fresh `aliased_from` data for each account whose email address
// appears in `affectedEmails` and update the reactive store in place.
// Called after an AliasToDelivery mutation so the affected account cards
// reflect the change.
//
const refreshAliasedFrom = async (affectedEmails) => {
  const targets = Object.values(emailAccountsData).filter((ea) =>
    affectedEmails.includes(ea.email_address),
  );
  await Promise.all(
    targets.map(async (ea) => {
      const res = await fetch(ea.url, { credentials: "same-origin" });
      if (res.ok) {
        const data = await res.json();
        ea.aliased_from = data.aliased_from;
      }
    }),
  );
};

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
      refreshAliasedFrom,
    };
  },
  delimiters: ["[[", "]]"],
});
app.mount("#asemail-vue-app");
