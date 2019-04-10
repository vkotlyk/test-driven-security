const userErrorPage = require('../errors/userErrorPage');
const {UNAUTHORIZED, BAD_GATEWAY} = require('../statusCodes');

function githubAuthenticationError(res) {
    return userErrorPage('login', res.status(UNAUTHORIZED), {error: 'Authentication with Github failed'});
}

function githubGatewayError(res) {
    return userErrorPage('login', res.status(BAD_GATEWAY), {error: 'Github authentication is temporarily down'});
}

module.exports = ({githubOauth}) => {
    const auth = (req, res) => {
        res.redirect(githubOauth.authorizationUri);
    };

    const callback = async (req, res) => {
        const {code} = req.query;

        try {
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
        } catch(e) {
            return githubGatewayError(res);
        }
    };

    return {auth, callback};
};