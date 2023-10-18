// AS Email App Vue/JS file
const initialData = JSON.parse(document.querySelector('#vue-data').textContent);
fetch(initialData.email_accounts_data[0].url,{method:"OPTIONS"}).
    then((response) => {
        if (!response.ok) {
            alert("HTTP Error: " + response.status);
        }
        return response.body;
    })
    .then((response) => {
        alert(response);
    });

function setupASEmail() {
    let app = new Vue({
        el: "#vue-app",
        delimiters: ['[[', ']]'],
        data: function() {
            return JSON.parse(document.querySelector('#vue-data').textContent);
        },
    });
}

setupASEmail();
const emailAccountCards = bulmaCollapsible.attach(".is-collapsible");
