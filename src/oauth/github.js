const oauth2 = require('simple-oauth2');
const GITHUB_OAUTH_CREDENTIALS = {
    client: {
        id: process.env.GITHUB_CLIENT_ID || 'github_client_id',
        secret: process.env.GITHUB_CLIENT_SECRET || 'github_client_secret'
    },
    auth: {
        tokenHost: 'https://github.com',
        authorizePath: '/login/oauth/authorize'
    }
};
const OAUTH2_CALLBACK_URI = process.env.OAUTH2_CALLBACK_URI || 'http://localhost:3000/callback';
const githubOauth = oauth2.create(GITHUB_OAUTH_CREDENTIALS);

const authorizationUri = githubOauth.authorizationCode.authorizeURL({
    redirect_uri: OAUTH2_CALLBACK_URI,
    scope: 'read:user', // openid when supported
});

module.exports = {
    authorizationUri
};