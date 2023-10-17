// AS Email App Vue/JS file
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
