function userErrorPage(resource, res, error) {
    res.format({
        'text/html'() {
            res.render(resource, error);
        },
        'application/json'() {
            res.json(error);
        }
    });
}

module.exports = userErrorPage;