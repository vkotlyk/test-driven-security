const userErrorPage = require('../errors/userErrorPage');
const {BAD_REQUEST} = require('../statusCodes');

const register = users => async (req, res) => {
    const {username, password} = req.body;

    try {
        await users.insertOne({username, password});
    } catch(e) {
        return userErrorPage('register', res.status(BAD_REQUEST), {error: e.message});
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