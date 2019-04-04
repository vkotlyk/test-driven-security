const bcrypt = require('bcryptjs');
const userErrorPage = require('../errors/userErrorPage');
const {CONFLICT} = require('../statusCodes');
const HASHING_ROUNDS = Number(process.env.BCRYPT_ROUNDS) || 1;
const debug = require('debug')('node-security');

const register = users => async (req, res) => {
    const {username, password} = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, HASHING_ROUNDS);
        await users.insertOne({username, password: hashedPassword});
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