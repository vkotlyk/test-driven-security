module.exports = (req, res) => {
    req.session.user = null;
    req.session.destroy();
    res.redirect('/');
};