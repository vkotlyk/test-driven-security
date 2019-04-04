const session = require('express-session');
const MongoStore = require('connect-mongo')(session);

module.exports = (cookie, url) => {
    const store = new MongoStore({url, ttl: 60 * 60});
    const userSession = session({
        secret: 'sessionsecret',
        resave: false,
        saveUninitialized: false,
        cookie,
        name: 'node-security',
        store
    });
    return {session: userSession, store};
};