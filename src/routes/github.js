const userErrorPage = require('../errors/userErrorPage');
const {UNAUTHORIZED} = require('../statusCodes');

function githubAuthenticationError(res) {
    return userErrorPage('login', res.status(UNAUTHORIZED), {error: 'Authentication with Github failed'});
}

module.exports = ({githubOauth}) => {
    const auth = (req, res) => {
        res.redirect(githubOauth.authorizationUri);
    };

    const callback = async (req, res) => {
        const {code} = req.query;

        const result = await githubOauth.getToken(code);
        const access_token = result.access_token;
        if(access_token) {
            req.session.regenerate(function (err) {
                req.session.user = {username: 'github user'};
                res.redirect('/');
            });
        } else {
            return githubAuthenticationError(res);
        }
    };

    return {auth, callback};
};