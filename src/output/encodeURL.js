const ESAPI = require('node-esapi');

function addURLEncoding(hbs) {
    hbs.registerHelper('link', function (value, options) {
        return ESAPI.encoder().encodeForURL(value);
    });
}

module.exports = addURLEncoding;