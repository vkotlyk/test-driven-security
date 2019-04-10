require('dotenv').config();
const initApp = require('./app');
const uuid = require('uuid/v4');

const PORT = process.env.PORT || 3000;
(async function main() {
    const app = await initApp({uuid});
    await app.setup();
    app.listen(PORT, () => {
        console.log(`Listening on port ${PORT}`);
    });
}());

