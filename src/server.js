require('dotenv').config();
const initApp = require('./app');
const githubOauth = require('./oauth/github');
const uuid = require('uuid/v4');

const PORT = process.env.PORT || 3000;
(async function main() {
    const app = await initApp({uuid, githubOauth});
    await app.setup();
    app.listen(PORT, () => {
        console.log(`Listening on port ${PORT}`);
    });
}());

