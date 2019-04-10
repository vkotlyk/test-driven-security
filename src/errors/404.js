const {NOT_FOUND} = require('../statusCodes');

module.exports = function (req, res, next) {
    res.status(NOT_FOUND).send("These Are Not the Droids You Are Looking For");
};