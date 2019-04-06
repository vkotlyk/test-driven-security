const home = posts => async function renderListPage(error, req, res) {
    const postsList = await posts.find({}).sort({_id: -1}).limit(10).toArray();
    const postsViewModel = {posts: postsList.map(p => p.text), error, csrfToken: req.csrfToken()};

    res.format({
        'text/html'() {
            res.render('home', {user: req.session.user, ...postsViewModel})
        },
        'application/json'() {
            res.json(postsViewModel);
        }
    });
};

module.exports = home;