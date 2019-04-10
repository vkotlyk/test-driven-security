module.exports = ({githubOauth}) => {
    const auth = (req, res) => {
        res.redirect(githubOauth.authorizationUri);
    };

    return {auth};
};