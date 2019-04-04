const sanitizeHtml = require('sanitize-html');

function addHtmlSanitization(hbs) {
    hbs.registerHelper('sanitize', function (value) {
        return sanitizeHtml(value, {
            allowedTags: ['b', 'i']
        });
    });
}

module.exports = addHtmlSanitization;