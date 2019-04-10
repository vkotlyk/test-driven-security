const helmet = require('helmet');

module.exports = helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        styleSrc: ['https://cdnjs.cloudflare.com']
    }
});