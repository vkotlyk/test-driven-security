const debug = require('debug')('node-security');
const {INTERNAL_SERVER_ERROR} = require('../statusCodes');

module.exports = function (err, req, res, next) {
    res.status(err.status || INTERNAL_SERVER_ERROR);
    debug(err);
    res.send(err.status > 499 ? "Something bad happened. It's not you it's us." : err.message);
};