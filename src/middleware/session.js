const session = require('express-session');

module.exports = (cookie) => {
    const userSession = session({
        secret: 'sessionsecret',
        resave: false,
        saveUninitialized: false,
        cookie,
        name: 'node-security',
    });
    return {session: userSession};
};