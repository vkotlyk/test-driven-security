const express = require('express');
const MongoClient = require('mongodb').MongoClient;
const hbs = require('hbs');
const path = require('path');

const DB = process.env.MONGODB_URI || 'mongodb://localhost:27017/node-security';

const bodyParser = require('body-parser');
const isAuthenticated = require('./middleware/authentication')();
const userSession = require('./middleware/session');

const home = require('./routes/home');
const addPost = require('./routes/addPost');
const login = require('./routes/login');
const logout = require('./routes/logout');
const register = require('./routes/register');


module.exports = async function initApp() {
    const connection = await MongoClient.connect(DB, {
        bufferMaxEntries: 0, useNewUrlParser: true
    });
    const db = connection.db();
    const users = db.collection('users');
    const posts = db.collection('posts');
    const {session} = userSession();

    const app = express();
    app.set("views", path.join(__dirname, "views"));
    app.set("view engine", "hbs");

    app.use(session);
    app.use(bodyParser.urlencoded({extended: false}));
    app.use(bodyParser.json());
    app.use(express.static(__dirname + '/public'));

    app.get('/', home(posts));
    app.get('/register', (req, res) => res.render('register'));
    app.post('/register', register(users));
    app.get('/login', (req, res) => res.render('login'));
    app.post('/login', login(users));
    app.get('/logout', logout);
    app.post('/post', isAuthenticated, addPost(posts));

    app.findUser = async (username) => {
        return await users.findOne({username});
    };

    app.setup = async () => {
        return await users.createIndex({username: 1}, {unique: true});
    };
    app.clean = async () => {
        await db.dropDatabase();
        return await app.setup();
    };
    app.close = async () => {
        await connection.close();
    };

    return app;
};

