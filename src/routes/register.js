const userErrorPage = require('../errors/userErrorPage');
const {CONFLICT} = require('../statusCodes');
const debug = require('debug')('node-security');

const register = users => async (req, res) => {
    const {username, password} = req.body;

    try {
        await users.insertOne({username, password});
    } catch(e) {
        debug(e);
        return userErrorPage('register', res.status(CONFLICT), {error: 'User already exists'});
    }
    res.format({
        'text/html'() {
            res.redirect('/login');
        },
        'application/json'() {
            res.json('Registered');
        }
    });
};

module.exports = register;