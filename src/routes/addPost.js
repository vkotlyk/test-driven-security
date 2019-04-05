const validatePost = require('../input/validatePost');

const addPost = ({posts, renderListPage}) => async (req, res) => {
    const {post} = req.body;
    const valid = validatePost({post});
    if(!valid) {
        const errorMsg = validatePost.errors.map(error => error.message).join(',');
        res.status(400);
        await renderListPage(errorMsg, req, res);
    } else {
        await posts.insertOne({text: post});
        res.redirect('/');
    }

};

module.exports = addPost;