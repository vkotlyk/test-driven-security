const {BAD_REQUEST} = require('../statusCodes');

const checker = csrf => function checkCsrf(req, res, next) {
    if (req.user && req.header('csrf-token')) {
        if (req.user['csrf-token'] === req.header('csrf-token')) {
            next();
        } else {
            res.status(BAD_REQUEST).send("Only authenticated users can post");
        }
    } else {
        return csrf(req, res, next);
    }
};

module.exports = checker;