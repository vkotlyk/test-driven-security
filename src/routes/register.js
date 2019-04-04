const register = users => async (req, res) => {
    const {username, password} = req.body;

    await users.insertOne({username, password});
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