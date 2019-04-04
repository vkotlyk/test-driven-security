const {BAD_REQUEST} = require('../statusCodes');

const isAuthenticated = () => (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.status(BAD_REQUEST).send("Only authenticated users can post");
    }
};

module.exports = isAuthenticated;