const jwt = require('jsonwebtoken');
const {BAD_REQUEST} = require('../statusCodes');

const isAuthenticated = jwtSecret => (req, res, next) => {
    if (req.session.user) {
        next();
    } else if (req.cookies.jwt) {
        const token = req.cookies.jwt;
        try {
            req.user = jwt.verify(token, jwtSecret);
            next();
        } catch (e) {
            res.status(BAD_REQUEST).send(e.message);
        }
    } else {
        res.status(BAD_REQUEST).send("Only authenticated users can post");
    }
};

module.exports = isAuthenticated;