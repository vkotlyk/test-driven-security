const rateLimit = require('express-rate-limit');

module.exports = () => rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 10 // limit each IP to 10 requests per windowMs
});