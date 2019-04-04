const userErrorPage = require('../errors/userErrorPage');
const {UNAUTHORIZED} = require('../statusCodes');

const login = users => async (req, res) => {
    const {username, password} = req.body;

    const user = await users.findOne({username, password});

    if (user) {
        req.session.regenerate(function(err) {
            req.session.user = {username: username.split('@')[0]};
            res.format({
                'text/html'() {
                    res.redirect('/');
                },
                'application/json'() {
                    res.json('Success');
                }
            });
        });
    } else {
        userErrorPage('login', res.status(UNAUTHORIZED), {error: 'Invalid credentials'});
    }
};

module.exports = login;