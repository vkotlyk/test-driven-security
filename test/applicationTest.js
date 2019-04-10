const httpClient = require('supertest');
const assert = require('assert');
const cheerio = require('cheerio');
const setCookieParser = require('set-cookie-parser');

const DEFAULT_USER_CREDENTIALS = {username: 'mark@gmail.com', password: 'correcthorsebatterystaple'};
const SESSION_COOKIE_NAME = 'node-security';
const OAUTH_CODE = '8f822999c6173a16cb46';
const STATE = '1234';
const uuid = () => STATE;

function times(n, character) {
    return Array(n + 1).join(character);
}

function toRequestCookies(responseCookies) {
    return Object.entries(responseCookies).map(([name, cookie]) => toRequestCookie(cookie)).join('; ');
}

function toRequestCookie({name, value}) {
    return `${name}=${value}`;
}

function extractSetCookies(result) {
    const pairs = (result.header['set-cookie'] || []).map(cookie => setCookieParser.parse(cookie)[0]).map(parsedCookie => ([parsedCookie.name, parsedCookie]));
    return pairs.reduce((acc, [name, cookie]) => ({...acc, [name]: cookie}), {});
}

describe('Node Security', function() {
    this.timeout(5000);

    let app, request;

    beforeEach(async () => {
        app = await require('../src/app.js')({uuid});
        await app.clean();
        request = httpClient(app);
    });

    afterEach(async () => {
        await app.close();
    });


    function registered({username, password}) {
        return register({username, password}).expect(302);
    }

    function register({username, password}) {
        return request
            .post('/register')
            .send(`username=${username}&password=${password}`)
            .set('Content-Type', 'application/x-www-form-urlencoded');
    }

    function registerJSON(credentials) {
        return request
            .post('/register')
            .send(credentials)
            .set('Content-Type', 'application/json')
            .set('Accept', 'application/json');
    }

    function login({username, password}) {
        return request
            .post('/login')
            .send(`username=${username}&password=${password}`)
            .set('Content-Type', 'application/x-www-form-urlencoded');
    }

    function loginWithCookie(cookies, {username, password}) {
        return login({username, password})
            .set('Cookie', toRequestCookie(cookies[SESSION_COOKIE_NAME]));
    }

    function loginJSON(credentials) {
        return request
            .post('/login')
            .send(credentials)
            .set('Content-Type', 'application/json')
            .set('Accept', 'application/json');
    }

    async function user({username, password} = DEFAULT_USER_CREDENTIALS) {
        await registered({username, password});
        const result = await login({username, password}).expect(302);
        return extractSetCookies(result);
    }

    async function userJSON({username, password} = DEFAULT_USER_CREDENTIALS) {
        await registerJSON({username, password}).expect(200);
        const response = await loginJSON({username, password});
        const cookies = extractSetCookies(response);
        const csrfToken = response.header['csrf-token'];
        return {cookies, csrfToken};
    }

    function obtainCSRFToken(cookies) {
        return openPage({
            url: '/',
            cookies
        }).then(response => {
            const $ = cheerio.load(response.text);
            return $('[name=_csrf]').attr('value');
        });
    }

    async function userWithCSRFToken({username, password} = DEFAULT_USER_CREDENTIALS) {
        const cookies = await user({username, password});
        const csrfToken = await obtainCSRFToken(cookies);

        return {cookies, csrfToken};
    }

    function post({cookies, csrfToken, msg}) {
        return request
            .post('/post')
            .send(`_csrf=${csrfToken}&post=${msg}`)
            .set('Content-Type', 'application/x-www-form-urlencoded')
            .set('Cookie', toRequestCookies(cookies))
    }

    function postJSON({cookies, csrfToken, msg}) {
        return request
            .post('/post')
            .send({post: msg})
            .set('csrf-token', csrfToken || '')
            .set('Content-Type', 'application/json')
            .set('Cookie', toRequestCookies(cookies));
    }

    function logout(cookies) {
        return request
            .get('/logout')
            .set('Cookie', toRequestCookies(cookies));
    }

    function openPage({url, cookies}) {
        return request
            .get(url)
            .set('Cookie', toRequestCookies(cookies));
    }

    function getJSON({url, cookies}) {
        return request.get(url)
            .set('Cookie', cookies ? toRequestCookies(cookies) : '')
            .set('Accept', 'application/json');
    }

    async function checkHeader(name, value) {
        const response = await request.get('/');

        assert.deepStrictEqual(response.header[name], value);
    }

    const responseContains = (selector, html) => response => {
        const $ = cheerio.load(response.text);
        assert.deepStrictEqual($(selector).html(),
            html);
    };

    it('Basic register/login/logout flow happy path', async function () {
        const cookies = await user();

        await openPage({url: '/', cookies}).expect(200, /<h2>Welcome home mark<\/h2>/);
        const {header: {location}} = await logout(cookies).expect(302);
        await openPage({url: location, cookies}).expect(200, /<h2>Welcome home <\/h2>/);
    });

    it.skip('Register duplicate user failure', async function () {
        await registered(DEFAULT_USER_CREDENTIALS);

        await register(DEFAULT_USER_CREDENTIALS).expect(409, /User already exists/);
    });

    it.skip('Invalid password', async function () {
        await registered(DEFAULT_USER_CREDENTIALS);

        await login({username: DEFAULT_USER_CREDENTIALS.username, password: 'invalid'})
            .expect(401, /Try again, Invalid credentials/);
    });

    async function invalidLogin() {
        await login({username: 'invalid@gmail.com', password: DEFAULT_USER_CREDENTIALS.password})
            .expect(401, /Try again, Invalid credentials/);
    }

    it.skip('Invalid login', async function () {
        await invalidLogin();
    });

    it.skip('Rate limit', async function () {
        for (let i = 0; i < 10; ++i) {
            await invalidLogin();
        }
        await login({username: 'invalid', password: 'pass'})
            .expect(429, /Too many requests, please try again later/);
    });

    it.skip('XSS prevention in HTML', async function () {
        const {cookies, csrfToken} = await userWithCSRFToken();

        const {header: {location}} = await post({
            cookies,
            csrfToken,
            msg: '<script>console.log(document.cookie)</script>'
        }).expect(302);

        await request.get(location)
            .expect(200)
            .then(responseContains('.original li', '&lt;script&gt;console.log(document.cookie)&lt;/script&gt;'));
    });

    it.skip('Whitelist allowed HTML tags', async function () {
        const {cookies, csrfToken} = await userWithCSRFToken();

        const {header: {location}} = await post({
            cookies,
            csrfToken,
            msg: '<b>bold</b><i>italic</i><p>paragraph</p><script>x=1</script>'
        }).expect(302);

        await request.get(location)
            .expect(200)
            .then(responseContains('.formatted li', '<b>bold</b><i>italic</i>paragraph'));
    });

    it.skip('Cookie is HTTPOnly and not accessible in JS', async function () {
        const cookies = await user();

        const parsedCookie = cookies[SESSION_COOKIE_NAME];

        assert.deepStrictEqual(parsedCookie.name, SESSION_COOKIE_NAME);
        assert.deepStrictEqual(parsedCookie.httpOnly, true);
    });

    it.skip('Session fixation is prevented with new session ID on each login', async function () {
        const cookies = await user();

        const loginResult1 = await loginWithCookie(cookies, DEFAULT_USER_CREDENTIALS).expect(302);
        const loginResult2 = await loginWithCookie(cookies, DEFAULT_USER_CREDENTIALS).expect(302);

        const cookie1 = extractSetCookies(loginResult1)[SESSION_COOKIE_NAME].value;
        const cookie2 = extractSetCookies(loginResult2)[SESSION_COOKIE_NAME].value;

        assert.ok(cookie1 && typeof cookie1 === 'string');
        assert.ok(cookie2 && typeof cookie2 === 'string');
        assert.ok(cookie1 !== cookie2);
    });

    it.skip('Password hashing', async function () {
        const IDENTICAL_PASSWORD = DEFAULT_USER_CREDENTIALS.password;
        await registered({username: 'mark@gmail.com', password: IDENTICAL_PASSWORD});
        await registered({username: 'sue@gmail.com', password: IDENTICAL_PASSWORD});

        const mark = await app.findUser('mark@gmail.com');
        const sue = await app.findUser('sue@gmail.com');

        assert.ok(mark.password !== sue.password); // different after hashing
    });

    it.skip('Cookies with JWT', async function () {
        const cookies = await user();

        const jwtCookie = cookies['jwt'];
        const jwt = jwtCookie.value;
        assert.ok(jwt && typeof jwt === 'string');
        assert.ok(jwtCookie.maxAge, 60);
    });

    it.skip('Basic register/login/post/read posts flow happy path for SPA', async function () {
        await registerJSON(DEFAULT_USER_CREDENTIALS).expect(200, '"Registered"');
        const loginResponse = await loginJSON(DEFAULT_USER_CREDENTIALS).expect(200, '"Success"');
        const {jwt} = extractSetCookies(loginResponse);
        const {header: {location}} = await postJSON({
            cookies: {jwt},
            msg: 'test post'
        }).expect(302);
        const listPostsResponse = await getJSON({url: location}).expect(200);

        assert.deepStrictEqual(JSON.parse(listPostsResponse.text).posts, ['test post']);
    });

    it.skip('Huge payload in request', async function () {
        const bigData = times(100000, 'A');
        await login({username: bigData, password: bigData})
            .expect(413, 'request entity too large');
    });

    it.skip('NoSQL injection prevention with sanitization', async function () {
        await registered(DEFAULT_USER_CREDENTIALS);
        await loginJSON({username: {'$gt': ''}, password: {'$gt': ''}})
            .expect(400, {
                "error": "Username is invalid",
                "hint": "Please use email address"
            });
    });

    it.skip('Blind NoSQL injection with a popular password', async function () {
        await registered({username: 'demouser1234@gmail.com', password: '123456'});
        await loginJSON({username: {'$regex': 'demo'}, password: '123456'})
            .expect(400, {
                "error": "Username is invalid",
                "hint": "Please use email address"
            });
    });

    it.skip('Only email allowed for username', async function () {
        await register({username: 'mark', password: 'pass'})
            .expect(400).expect(/Username is invalid/).expect(/Please use email address/);

    });

    it.skip('Weak password strength not allowed', async function () {
        await register({username: DEFAULT_USER_CREDENTIALS.username, password: 'pass'})
            .expect(400).expect(/Password too week/).expect(/Add another word or two. Uncommon words are better./);
    });

    it.skip('JSON pollution in register', async function () {
        await registerJSON({username: {}}).expect(400, {
            "error": "Username is invalid",
            "hint": "Please use email address"
        });
        await registerJSON({username: {toString: null}}).expect(400, {
            "error": "Username is invalid",
            "hint": "Please use email address"
        });
        await registerJSON({username: DEFAULT_USER_CREDENTIALS.username, password: {}}).expect(400, {
            "error": "Password is invalid",
            "hint": "Please use a string value"
        });
        await registerJSON({username: DEFAULT_USER_CREDENTIALS.username, password: {toString: null}}).expect(400, {
            "error": "Password is invalid",
            "hint": "Please use a string value"
        });
        await registerJSON(null).expect(400, "Unexpected token n in JSON at position 0");
        await registerJSON(false).expect(400, "Unexpected token f in JSON at position 0");
    });

    it.skip('JSON pollution in login', async function () {
        await loginJSON({username: {}}).expect(400, {
            "error": "Username is invalid",
            "hint": "Please use email address"
        });
        await loginJSON({username: {toString: null}}).expect(400, {
            "error": "Username is invalid",
            "hint": "Please use email address"
        });
        await loginJSON({username: DEFAULT_USER_CREDENTIALS.username, password: {}}).expect(400, {
            "error": "Password is invalid",
            "hint": "Please use a string value"
        });
        await loginJSON({username: DEFAULT_USER_CREDENTIALS.username, password: {toString: null}}).expect(400, {
            "error": "Password is invalid",
            "hint": "Please use a string value"
        });
        await loginJSON(null).expect(400, "Unexpected token n in JSON at position 0");
        await loginJSON(false).expect(400, "Unexpected token f in JSON at position 0");
    });

    it.skip('Post validation with JSON schema', async function () {
        const cookies = await user();

        await post({cookies, msg: ''}).expect(400, /Please use between 1 and 140 characters/);
        await post({cookies, msg: 'a'}).expect(302);
        await post({cookies, msg: times(140, 'a')}).expect(302);
        await post({cookies, msg: times(141, 'a')}).expect(400, /Please use between 1 and 140 characters/);
        await postJSON({cookies, msg: {}}).expect(400, /Please use between 1 and 140 characters/);
    });

    it.skip('Context aware XSS', async function () {
        const cookies = await user();

        await post({cookies, msg: 'javascript:alert(1)'});

        await openPage({url: '/', cookies}).expect(200, /href="javascript%3Aalert%281%29"/);
    });

    it.skip('CSRF token generation', async function () {
        const cookies = await user();

        const csrfToken = await obtainCSRFToken(cookies);

        assert.ok(csrfToken);
    });

    it.skip('Reject requests without CSRF token', async function () {
        const {cookies, csrfToken} = await userWithCSRFToken();

        await post({cookies, csrfToken: '', msg: 'irrelevant'}).expect(403);
    });

    it.skip('Secure JWT token against CSRF - happy path', async function () {
        const {cookies, csrfToken} = await userJSON();
        const {jwt} = cookies;

        await postJSON({cookies: {jwt}, csrfToken, msg: 'irrelevant'}).expect(302);
    });

    it.skip('Secure JWT token against CSRF - no token', async function () {
        const {cookies} = await userJSON();
        const {jwt} = cookies;

        await postJSON({cookies: {jwt}, csrfToken: '', msg: 'irrelevant'}).expect(403);
    });

    it.skip('Secure JWT token against CSRF - no jwt cookie', async function () {
        const {csrfToken} = await userJSON();

        await postJSON({cookies: {}, csrfToken, msg: 'irrelevant'}).expect(400);
    });

    it.skip('CSRF protection with SameSite cookies', async function () {
        const cookies = await user();

        assert.deepStrictEqual(cookies[SESSION_COOKIE_NAME].sameSite, 'Strict');
        assert.deepStrictEqual(cookies['jwt'].sameSite, 'Strict');
    });

    it.skip('Obfuscate your tech stack', async function () {
        await checkHeader('x-powered-by', undefined);
    });

    it.skip('Disable browser DNS prefetching', async function () {
        await checkHeader('x-dns-prefetch-control', 'off');
    });

    it.skip('Prevent clickjacking from an iframe', async function () {
        await checkHeader('x-frame-options', 'SAMEORIGIN');
    });

    it.skip('Prevent browser from guessing MIME type', async function () {
        await checkHeader('x-content-type-options', 'nosniff');
    });

    it.skip('Prevent HTTP downgrade when already on HTTPS (HSTS)', async function () {
        await checkHeader('strict-transport-security', 'max-age=15552000; includeSubDomains');
    });

    it.skip('Content Security Policy (CSP)', async function () {
        await checkHeader('content-security-policy', "default-src 'self'; style-src https://cdnjs.cloudflare.com; require-sri-for style");
    });

    it.skip('OAuth2: Prepare Github authorize path', async function () {
        const response = await request.get('/auth').expect(302);

        assert.deepStrictEqual(response.header.location,
            'https://github.com/login/oauth/authorize?response_type=code&client_id=github_client_id&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=read%3Auser');
    });

    function oauthFlow(state) {
        return async function(status, body) {
            const authResponse = await request.get('/auth').expect(302);
            const cookies = extractSetCookies(authResponse);
            return openPage({url: `/callback?code=${OAUTH_CODE}&state=${state}`, cookies}).expect(status, body);
        };
    }

    it.skip('OAuth2: exchange code for token', async function () {
        githubOauth.getToken = args => {
            githubOauth.getToken.invokedWith = args;
            return Promise.resolve({access_token: 'token_to_github_api'});
        };
        const callbackResponse = await oauthFlow(STATE)(302, /Found/);
        await openPage({url: callbackResponse.header.location, cookies: extractSetCookies(callbackResponse)}).expect(200, /github user/);

        assert.deepStrictEqual(githubOauth.getToken.invokedWith, OAUTH_CODE);
    });

    it.skip('OAuth2: incorrect or expired code', async function () {
        githubOauth.getToken = args => {
            githubOauth.getToken.invokedWith = args;
            return Promise.resolve({error: 'bad_verification_code'});
        };
        await oauthFlow(STATE)(401, /Authentication with Github failed/);

        assert.deepStrictEqual(githubOauth.getToken.invokedWith, OAUTH_CODE);
    });

    it.skip('OAuth2: provider error', async function () {
        githubOauth.getToken = args => {
            githubOauth.getToken.invokedWith = args;
            return Promise.reject("Github error");
        };
        await oauthFlow(STATE)(502, /Github authentication is temporarily down/);

        assert.deepStrictEqual(githubOauth.getToken.invokedWith, OAUTH_CODE);
    });

    it.skip('OAuth2: no state passed to callback', async function () {
        await oauthFlow()(401, /Authentication with Github failed/);
    });

    it.skip('OAuth2: different state passed to callback', async function () {
        await oauthFlow('HACKED_STATE')(401, /Authentication with Github failed/);
    });

    it.skip('OAuth2: no existing session', async function () {
        await request.get('/callback?code=HACKED&state=HACKED').expect(401, /Authentication with Github failed/);
    });

    it.skip('Prevent DoS with password limit', async function () {
        this.timeout(2000);
        const veryBigData = times(1000, 'A');
        const bigData = times(129, 'A');
        const mediumData = times(128, '💩'); // '💩'.length === 2
        await register({username: DEFAULT_USER_CREDENTIALS.username, password: veryBigData})
            .expect(400, /Please use a password up to 128 characters/);
        await register({username: DEFAULT_USER_CREDENTIALS.username, password: bigData})
            .expect(400, /Please use a password up to 128 characters/);
        await register({username: DEFAULT_USER_CREDENTIALS.username, password: mediumData})
            .expect(400, /Password too week/);
    });

});
