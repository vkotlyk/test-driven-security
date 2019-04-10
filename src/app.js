const express = require('express');
const MongoClient = require('mongodb').MongoClient;
const hbs = require('hbs');
const path = require('path');

const DB = process.env.MONGODB_URI || 'mongodb://localhost:27017/node-security';
const ENV = process.env.NODE_ENV || 'development';
const isProduction = ENV.toLowerCase() === 'production';
const COOKIE_OPTIONS = {secure: isProduction, httpOnly: true, sameSite: 'strict'};
const JWT_SECRET = process.env.JWT_SECRET || 'jwtsecret';

require('./output/sanitizeHtml')(hbs);
require('./output/encodeURL')(hbs);

const bodyParser = require('body-parser');
const csrf = require('csurf')();
const checkCsrf = require('./middleware/checkCsrf')(csrf);
const isAuthenticated = require('./middleware/authentication')(JWT_SECRET);
const userSession = require('./middleware/session');
const cookieParser = require('cookie-parser');
const limiter = require('./middleware/rateLimit');
const helmet = require('helmet');
const enforceSsl = require('express-enforces-ssl');

const home = require('./routes/home');
const addPost = require('./routes/addPost');
const login = require('./routes/login');
const logout = require('./routes/logout');
const register = require('./routes/register');
const error = require('./errors/error');


module.exports = async function initApp({uuid}) {
    const connection = await MongoClient.connect(DB, {
        bufferMaxEntries: 0, useNewUrlParser: true
    });
    const db = connection.db();
    const users = db.collection('users');
    const posts = db.collection('posts');
    const {session, store} = userSession(COOKIE_OPTIONS, DB);
    const renderListPage = home(posts);

    const app = express();
    app.set("views", path.join(__dirname, "views"));
    app.set("view engine", "hbs");

    if(isProduction) {
        app.set("trust proxy", true);
        app.use(enforceSsl());
    }
    app.use(helmet());
    app.use(cookieParser());
    app.use(session);
    app.use(bodyParser.urlencoded({extended: false}));
    app.use(bodyParser.json());
    app.use(express.static(__dirname + '/public'));

    app.get('/', csrf, (req, res) => renderListPage(null, req, res));
    app.get('/register', (req, res) => res.render('register'));
    app.post('/register', register(users));
    app.get('/login', (req, res) => res.render('login'));
    app.post('/login', limiter(), login({users, uuid, jwtSecret: JWT_SECRET, cookieOptions: COOKIE_OPTIONS}));
    app.get('/logout', logout);
    app.post('/post', isAuthenticated, checkCsrf, addPost({posts, renderListPage}));
    app.use(error);

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
        await store.close();
        await connection.close();
    };

    return app;
};

