const addPost = posts => async (req, res) => {
    const {post} = req.body;
    await posts.insertOne({text: post});
    res.redirect('/');
};

module.exports = addPost;