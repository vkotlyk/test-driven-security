module.exports = ({githubOauth}) => {
    const auth = (req, res) => {
        res.redirect(githubOauth.authorizationUri);
    };

    const callback = async (req, res) => {
        const {code} = req.query;

        const result = await githubOauth.getToken(code);
        const access_token = result.access_token;

        req.session.regenerate(function (err) {
            req.session.user = {username: 'github user'};
            res.redirect('/');
        });
    };

    return {auth, callback};
};