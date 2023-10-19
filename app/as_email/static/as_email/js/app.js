// AS Email App Vue/JS file
//
import { createApp, ref, onMounted } from "https://unpkg.com/vue@3/dist/vue.esm-browser.js";

// Get the data that the as_email service filled the document with that
// contains information about all the EmailAccount's.
//
// It also contains the DRF `options` data for the EmailAccount object so we
// know what fields exist, what types they are, read only or not, and
// descriptions.
//
const initialData = JSON.parse(document.getElementById('vue-data').textContent);
console.log(initialData.email_account_list_url);
// Hook up the 'bulma-collapsible' support js code for collapsing and expanding
// the EmailAccount cards.
//
const emailAccountCards = bulmaCollapsible.attach(".is-collapsible");

let res = await fetch(initialData.email_accounts_data[0].url, {method:"OPTIONS"});
let emailAccountFieldsOptions = await res.json();
let emailAccountFields = emailAccountFieldsOptions.actions.PUT;
console.log(emailAccountFields);

createApp({
    setup() {
        const myTitle = ref('Hello Vue!');
        return {
            myTitle
        };
    },
    delimiters: ['[[', ']]'],
}).mount('#vue-app');
