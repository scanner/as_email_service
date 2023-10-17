// AS Email App Vue/JS file
function setupASEmail() {
    let app = new Vue({
        el: "#vue-app",
        delimiters: ['[[', ']]'],
        data: {
            myTitle: 'Hello Vue!',
        },
        // data: function() {
        //     return document.querySelector('#email-accounts-data').innerText;
        // },
    });
}
