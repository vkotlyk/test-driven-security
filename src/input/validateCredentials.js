const validator = require('validator');

function validateCredentials({username, password}) {
    if (!validator.isEmail(String(username))) {
        return {error: "Username is invalid", hint: "Please use email address"};
    }
}

module.exports = validateCredentials;