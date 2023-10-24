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

// Hook up the 'bulma-collapsible' support js code for collapsing and expanding
// the EmailAccount cards.
//
const emailAccountCards = bulmaCollapsible.attach(".is-collapsible");
const bulmaTags = BulmaTagsInput.attach();

// Example using `await` and `fetch` together.
//
let res = await fetch(
    initialData.email_accounts_data[0].url,
    {method:"OPTIONS"}
);
if (res.ok) {
    let emailAccountFieldsOptions = await res.json();
    let emailAccountFields = emailAccountFieldsOptions.actions.PUT;
    console.log(emailAccountFields);
} else {
    console.log(`Unable to get field data for EmailAccount: ${res.statusText}(${res.status})`);
}

const origTitle = "yup, you got that";

//////////////////////////////////////////
//
// Vue reference objects
//
const myTitle = ref(origTitle);


//////////////////////////////////////////
//
// Vue component functions
//
function update_foo() {
    myTitle.value="Clicked";
    setTimeout(() => myTitle.value=origTitle, 5000);
}

//////////////////////////////////////////
//
// Root Vue app
//
const app = createApp({
    setup() {
        return {
            myTitle,
            update_foo
        };
    },
    delimiters: ['[[', ']]'],
});
app.mount('#vue-app');
