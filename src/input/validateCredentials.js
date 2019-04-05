const validator = require('validator');

function validateCredentials({username, password}) {
    if (typeof username !== 'string' || !validator.isEmail(username)) {
        return {error: "Username is invalid", hint: "Please use email address"};
    }
    if (typeof password !== "string") {
        return {error: "Password is invalid", hint: "Please use a string value"};
    }
}

module.exports = validateCredentials;