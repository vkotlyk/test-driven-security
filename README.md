# Test Driven Web App Security
## Secure your Node.js Web Application guided by tests.

Most security materials for web developers are either theoretical or require
sophisticated setup (VMs, containers etc.).

The goal of this workshop is to capture common web application attacks
as a suite of tests that run in-process with your Node.js application.

We gonna write application code addressing those attacks.
Step by step. I want you to understand every single line we put into the codebase.

Also we'll keep the examples minimal to capture the essence of the
security problems without unnecessary distractions.

## Setting the context [starter]

You inherited an app with a simple register/login/logout flow.

Start MongoDB in the background.

Then run your app:
```npm i```
```npm start```

Go to localhost:3000

Try to register and login with any email and any password.

Same login flow is also automated in test/applicationTest.

You can run it with:
```npm test```

Some important notes about our test:
* we're cleaning database before each test run
* we're closing DB connection after each test so that test framework can stop running
* we're simulating browser form submit with x-www-form-urlencoded Content-Type
* we're sending cookies the same way browser would do it

## Registration error leakage [registration_error]

Try to register the same user twice. What error are we getting?

Database errors should not leak to the user space.

There's a corresponding test describing desired behavior: 'Register duplicate user failure'.

Unskip the test and make it green.

If you want to maintain low-level error message for logs use the following code:
```javascript
const debug = require('debug')('node-security');
debug(e);
```

## Invalid login and password feedback [invalid_login_credentials]

Currently we provide no feedback on invalid login credentials.

Let's add the 'Invalid credentials' message without disclosing which part is invalid.

Add this snippet to views/login.hbs:
```javascript
{{#if error}}
    <h2>Try again, {{error}}</h2>
{{/if}}
```

There should be 2 corresponding tests ('Invalid password' and 'Invalid login') that should go green.

## Rate limit [rate_limit]

Let's simulate a situation with an attacker making an excessive number of
login attempts. We'd like to rate limit those attempts up to 10 per minute.
In our [threat modeling](https://www.thoughtworks.com/radar/techniques/threat-modeling)
we found that we're more concerned with an attacker trying to collect
as many credentials as possible rather that attacking just one specific user.
That's why we gonna rate limit based on IP, not login.

We could move this capability to the infrastructure (e.g. load balancer)
but depending on your production setup and requirements you may want to
do it in your Node.js application.

There's a failing 'Rate limit' test that should guide you.

Create middleware/rateLimit.js
```javascript
const rateLimit = require('express-rate-limit');

module.exports = () => rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 10 // limit each IP to 10 requests per windowMs
});
```
In app.js:
```javascript
const limiter = require('./middleware/rateLimit');
app.post('/login', limiter(), login(users));
```
We want to instantiate a new limiter per app invocation.
Current rate limit has in-memory counter store, in production
you may consider writing the counter value to a database.

If you don't want to block users but slow them down instead
there's another [module](https://www.npmjs.com/package/express-slow-down).

## Brute force attacks prevention - other mechanisms

After a few failed login attempts layer those mechanisms:
- CAPTCHA (tricky for humans, machines can solve them nowadays)
- temporary lockout and email secret link to unlock

## Script injection into HTML [xss_html]

After our users log in they can post messages.

Add a post with the following text:
```
<script>console.log(document.cookie)</script>
```

We've just exposed ourselves to XSS attack.
Obviously the attacker wouldn't just console.log but
would try to access your cookies, local storage etc. and send
 this data to their server with img/XMLHttpRequest/fetch etc.

There's a test 'XSS prevention in HTML' telling us to escape HTML content.

In the views/home.hbs replace {{{}}} with {{}} to escape HTML content. It should make the test green.

## Sanitizing HTML [sanitizing_html]

Sometimes we need to allow users to put some HTML as valid input.
Let's allow bold and italic tags in our case and create preview list.

views/home.hbs
```
<h2>Original</h2>
<ol class="original">
    {{#each posts}}
        <li>{{this}}</li>
    {{/each}}
</ol>
<h2>Preview</h2>
<ol class="formatted">
    {{#each posts}}
        <li>{{{this}}}</li>
    {{/each}}
</ol>
```

Try to post this message:
<b>bold</b><i>italic</i><p>paragraph</p><script>x=1</script>

Same action is captured in a test called 'Whitelist allowed HTML tags'.

We'd expect paragraph and script to be removed.

Create output/sanitizeHtml.js
```javascript
const sanitizeHtml = require('sanitize-html');

function addHtmlSanitization(hbs) {
    hbs.registerHelper('sanitize', function (value) {
        return sanitizeHtml(value, {
            allowedTags: ['b', 'i']
        });
    });
}

module.exports = addHtmlSanitization;
```
We're extending our template engine with HTML sanitization capability.
Please note that sanitize-html removes most tags leaving the content,
but for the script, style and textarea everything is removed.

In the hbs file update this line:
```html
<li>{{{sanitize this}}}</li>
```

And finally add this extension to our template engine in app.js
```javascript
require('./output/sanitizeHtml')(hbs);
```

## Hardening HTTP session [hardening_http_session]

In the previous exercise JS could access our cookie. Let's fix it.

The simplest option is to change httpOnly to true.
But we want to also make sure that cookies are only served over HTTPS
in production.

app.js
```javascript
const ENV = process.env.NODE_ENV || 'development';
const isProduction = ENV.toLowerCase() === 'production';
const COOKIE_OPTIONS = {secure: isProduction, httpOnly: true};

const {session} = userSession(COOKIE_OPTIONS);
```
httpOnly: true means JS won't be able to access our session after XSS attack.

middleware/session.js
```javascript
module.exports = cookie => {
    const userSession = session({
        ...
        cookie
    });
    return {session: userSession};
};
```

Unskip the following test: 'Cookie is HTTPOnly and not accessible in JS'

## Session fixation [session_fixation]

Open browser in normal and incognito mode.

In the incognito mode create attacker account.

Log in and log out to obtain session ID.

In the application tab in Chrome copy session ID.

Paste session ID in the normal tab and create victim account.

Once you log in as a victim refresh attackers incognito tab.

You should be logged-in in both tabs.

We'd like express-session to generate a new session ID on each successful login.

routes/login.js
```javascript
req.session.regenerate(function(err) {
    req.session.user = {username: username.split('@')[0]};
    res.format({
        'text/html'() {
            res.redirect('/');
        },
        'application/json'() {
            res.json('Success');
        }
    });
});
```

Note: if you decide to generate session IDs [yourself](https://github.com/expressjs/session#genid) please make sure
it's difficult to guess them by the attacker.
Preferably stick to the default express-session generator.

## Persisting session across server restarts [session_store]

Please note that every time we restart our server sessions are gone.
Also if we start running our app on many servers we don't share
session information across our backends which leads to questionable
solutions like sticky sessions.
Let's store our sessions in MongoDB.

middleware/session.js
```javascript
const MongoStore = require('connect-mongo')(session);

module.exports = (cookie, url) => {
    const store = new MongoStore({url, ttl: 60 * 60});
    const userSession = session({
        ...
        store
    });
    return {session: userSession, store};
};
```

app.js
```javascript
const {session, store} = userSession(COOKIE_OPTIONS, DB);

app.close = async () => {
    await store.close();
    await connection.close();
};
```
We need to close our store same way we close our regular connection
so that tests don't hang up.

Log in to your app and restart the server. See if session is persisted.
TTL is application specific. We go for 1h session expiry if user is inactive.
Cat pictures website may have 1 month long sessions while bank may go for 10 minutes.

Also please run all our tests to make sure we haven't introduced regression errors.

## Password hashing [bcrypt]

Imagine your database with passwords leaked in a data breach.
Even though your website may serve cat pictures, some users
use the same password for their bank account.

Note: https://haveibeenpwned.com/ has some famous data breaches.

Or imagine one of your insiders impersonating user by looking up the password
in a DB.

Currently we store passwords in plain text.

So we could use encryption/decryption but even better option is to use hashing
which is a one way operation.

For the hashing function we should use a slow algorithm e.g. bcrypt.
It's one of those rare cases where slow is desirable.

routes/register.js
```javascript
const bcrypt = require('bcryptjs');

const hashedPassword = await bcrypt.hash(password, 12);
await users.insertOne({username, password: hashedPassword});
```

routes/login.js
```javascript
const bcrypt = require('bcryptjs');

const user = await users.findOne({username});
if(user && await bcrypt.compare(password, user.password)) {}
```

Run all your existing tests. They are much slower now.

Check the number 12 in bcrypt.hash().

12 is the number of rounds. The more rounds the slower the algorithm
and more difficult it is to brute force the attack.

I found that 12 rounds takes more than 200ms and less than 1 second on my machine.
14 rounds takes more than 1s.

12 rounds = 2^12 iterations

Let's speed up our tests:
routes/register.js
```javascript
const HASHING_ROUNDS = Number(process.env.BCRYPT_ROUNDS) || 1;

const hashedPassword = await bcrypt.hash(password, HASHING_ROUNDS);
```

To set proper value for production we can change package.json
```
"start": "NODE_ENV=production BCRYPT_ROUNDS=12 node src/server.js"
```

Since bcrypt stores the number of rounds inside the hash you can increase
the work factor without breaking existing passwords.
All the new passwords will get the new work factor.

## bcrypt and salt [bcrypt_salt]

Unskip the test called 'Password hashing'.

What's interesting is that 2 users with identical passwords have different hashed passwords.

The reason for that is bcrypt using random salt to generate those hashes.
Salt itself is included in the hashed password itself so salt generation
doesn't need to leak into the user space.
It's nicely hidden inside the bcrypt hashing algorithm.
Good Software Design TM.
Please note that salt doesn't require any special protection,
it can live encoded inside your hash.

## The Case for JSON Web Token (JWT)

So far we've been authenticating our users with SessionID stored in cookies.

![Cookies and SESSIONID](https://i.imgur.com/1MKUqTV.jpg?1)

One drawback of this approach is that each request after first login has to go to the database.

Welcome JWT!

![Cookies and JWT](https://i.imgur.com/AJMH7D2.jpg?1)

If we replace SessionID with JWT we can perform all subsequent checks
in memory without going back to the database.

What are practical implications?
* lower impact on our database
* stateless authentication: we can move the code after login to a separate service and it can
check users in-memory without contacting service with users.

## JWT signing [jwt_signing]

So imagine we'd like to move POST /post handling to a separate service
but still allow only logged-in users to POST new entries.

Let's add JWT tokens to our application.

app.js
```javascript
const JWT_SECRET = process.env.JWT_SECRET || 'jwtsecret';

app.post('/login', limiter(), login({users, jwtSecret: JWT_SECRET, cookieOptions: COOKIE_OPTIONS}))
```
We' need to change the signature of login to inject jwtSecret and cookieOptions.

routes/login.js
```javascript
const jwt = require('jsonwebtoken');

const login = ({users, jwtSecret, cookieOptions}) => async (req, res) => {
    const token = jwt.sign({username}, jwtSecret, {expiresIn: '1h'});
    res.cookie('jwt', token, {...cookieOptions, maxAge: 1 * 60 * 1000});

    req.session.regenerate();
}
```
We sign our JWT token with a secret. We gonna use symmetrical key in this example
but we could also use private key instead.

Out JWT token will be valid for 1 hour.

Let's see if JWT cookie is being set in test 'Cookies with JWT'.

Try to console.log your token and paste it into jwt.io.
Important observations:
* anyone can see the payload inside JWT token so don't put any secrets there
* only key owners can verify signature


You may be wondering why we don't follow most tutorials telling you to put
JWT token in the response body, then store it in local storage and then send it with Authorization
header to the server.

Well, it opens possibility of the XSS attack. localStorage is not the most secure
place and HTTPOnly cookies are much better place to store your tokens.

## JWT verification [jwt_verification]

To verify JWT inside a cookie we need to add cookie-parser module.
It is similar to express-session but allows to parse custom cookies,
not just the ones managed by express-session.

app.js
```javascript
const cookieParser = require('cookie-parser');
const isAuthenticated = require('./middleware/authentication')(JWT_SECRET);

app.use(cookieParser());
```
Cookie parse will populate req.cookies.
Then verify method will
check if token is valid. Please note that to verify token
we don't need to go to a database. Everything can be done in memory
as long as you have a secret.

middleware/authentication.js
```javascript
const jwt = require('jsonwebtoken');
const {BAD_REQUEST} = require('../statusCodes');

const isAuthenticated = jwtSecret => (req, res, next) => {
    if (req.session.user) {
        next();
    } else if (req.cookies.jwt) {
        const token = req.cookies.jwt;
        try {
            req.user = jwt.verify(token, jwtSecret);
            next();
        } catch (e) {
            res.status(BAD_REQUEST).send(e.message);
        }
    } else {
        res.status(BAD_REQUEST).send("Only authenticated users can post");
    }
};

module.exports = isAuthenticated;
```
We passed the same JWT_SECRET to our middleware as we used during login.

Rune this test: 'Basic register/login/post/read posts flow happy path for SPA'.
It deliberately simulates SPA issuing requests and not using node-security
cookie, only jwt cookie.

## Why JWT may not be a good idea for Single Page Apps sessions [jwt_critique]

Please note that JWT tokens are not the most convenient solution for session management
due to several things you have to implement yourself:
* keeping tokens alive and refreshing them
* revoking access by blacklisting some tokens
* logout is tricky since tokens have expiry date
Cookies are much simpler and just work out of the box.

More:
http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/
http://cryto.net/~joepie91/blog/2016/06/19/stop-using-jwt-for-sessions-part-2-why-your-solution-doesnt-work/

## Handling large payload and error messages [big_payload]

Let's simulate a scenario when user submits large payload exceeding 100kb.
This value is a default max request body size for the [body parser](https://github.com/expressjs/body-parser#limit).

Relevant test: 'Huge payload in request'.

We're expecting 413 Payload Too Large with a corresponding body error message.
What we're getting instead is full stack trace.
This is default express behavior that's convenient for development
but unacceptable for production.

We need to add custom error handler and hide those errors:

errors/error.js
```javascript
module.exports = function (err, req, res, next) {
    res.status(err.status || 500);
    res.send(err.message);
};
```

app.js
```javascript
const error = require('./errors/error');

// after all routes
app.use(error);
```

## NoSQL injection [nosql_injection]

Let's continue our exploration of malicious input data.
This time we'll attempt NoSQL injection.

Relevant test: 'NoSQL injection prevention with sanitization'

When we run this test and set a debugger in the POST /login we'll find out
that the attacker read the user and then the application crashed
on bcrypt.compare.

## Blind NoSQL injection with popular passwords [blind_nosql_injection]

Before we fix our code let's try another attack

Relevant test: 'Blind NoSQL injection with a popular password'

This time we find a first user matching regex and use a [popular password](https://en.wikipedia.org/wiki/List_of_the_most_common_passwords).

Instead of 400 we've just managed to log in to the victim's account.

## Validate user input [validate_input]

Let's validate that username is an email.

Please try not to use regular expressions as it's easy to perform ReDOS attack.
You should prefer mature validation libraries instead.

We have several libraries to choose from:
* [validator.js](https://github.com/chriso/validator.js)
* [joi](https://github.com/hapijs/joi)
* [ajv](https://github.com/epoberezkin/ajv)
* [express-validator](https://github.com/express-validator/express-validator)

I'll use validator.js which is the simplest one and allows to easily write
custom error messages. Schema based approach like joi or ajv have more difficult
to customize custom error messages, but lead to more concise code.

input/validateCredentials.js
```javascript
const validator = require('validator');

function validateCredentials({username, password}) {
    if (!validator.isEmail(String(username))) {
        return {error: "Username is invalid", hint: "Please use email address"};
    }
}

module.exports = validateCredentials;
```

routes/login.js
```javascript
const {UNAUTHORIZED, BAD_REQUEST} = require('../statusCodes');
const validateCredentials = require('../input/validateCredentials');

const error = validateCredentials({username, password});
if (error) return userErrorPage('login', res.status(BAD_REQUEST), error);
```

Now all tests should go green again.

## Validate input with a hint [validation_hint]

Relevant test: 'Only email allowed for username'

When user tries to register we want to provide feedback why it may be failing.

Add the same validation to register.

routes/register.js
```
const {CONFLICT, BAD_REQUEST} = require('../statusCodes');
const validateCredentials = require('../input/validateCredentials');

const error = validateCredentials({username, password});
if (error) return userErrorPage('register', res.status(BAD_REQUEST), error);
```
In future we may consider extracting common code to a middleware, but
for now let's leave it as it is.

Also, we need to add extra failing reason hint to the HTML:
views/register.hbs
```html
{{#if error}}
    <h2 class="registration-error">{{error}}</h2>
    <p class="registration-hint">{{hint}}</p>
{{/if}}
```

## Password policy [password_policy]

[XKCD](https://xkcd.com/936/) nicely summarizes problems with modern password requirements.

Let's add password strength check to our registration so that only strong enough
passwords are allowed.

'Weak password strength not allowed' test will guide us.

routes/register.js
```javascript
const estimatePasswordStrength = require('zxcvbn');

const passwordStrength = estimatePasswordStrength(password);

if (passwordStrength.score <= 1) {
    const error = {error: "Password too week", hint: passwordStrength.feedback.suggestions.join(' ')};
    return userErrorPage('register', res.status(BAD_REQUEST), error);
}
```

Run all tests. One of the old tests shouldn't make sense any more so remove it.

## JSON pollution [json_pollution]

What if the username/password is not a string but e.g. {}?
What about a scenario when username/password is a malicious object with toString?
What if our input JSON is null or some other primitive value?

'JSON pollution in register' and 'JSON pollution in login' have those cases covered.

JSON body parser by default is in so-called [strict mode](https://github.com/expressjs/body-parser#strict)
and only allows for objects and arrays.
But once we get and object and array we need to exclude those since we expect
a string. validator.js works on strings.

input/validateCredentials.js
```javascript
function validateCredentials({username, password}) {
    if (typeof username !== 'string' || !validator.isEmail(username)) {
        return {error: "Username is invalid", hint: "Please use email address"};
    }
    if (typeof password !== "string") {
        return {error: "Password is invalid", hint: "Please use a string value"};
    }
}
```

Note: when using query params or HTML forms we can also
prepare non string input by sending same param multiple times.
It's then parsed by express and an array.

## Input validation with schema validators [schema_validator]

Make sure that POST /login has it's input validated too.
Posts should not allow longer string than 140 characters.
This time we'll see how to use schema based validators.

'Post validation with JSON schema' test is our guide.

input/validatePost.js
```javascript
const Ajv = require('ajv');
const AjvErrors = require('ajv-errors');

const ajv = new Ajv({allErrors: true, jsonPointers: true});
AjvErrors(ajv, {singleError: true});
const schema = {
    title: 'PostSubmission',
    properties: {
        post: {type: 'string', minLength: 1, maxLength: 140}
    },
    additionalProperties: false,
    required: ['post'],
    errorMessage: 'Please use between 1 and 140 characters'
};
const validatePost = ajv.compile(schema);

module.exports = validatePost;
```
We use ajv since it's based on JSON Schema standard and works
both client and server side.
We also added ajv-errors extension to support custom error messages.

routes/addPost.js
```javascript
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
```
We use Post/Redirect/Get pattern only on success.
On error we return 400 and render list page with errors.
renderListPage is a function we inject to render the same page that triggered
the request.

Where does renderListPage come from?
routes/home.js
```
const home = posts => async function renderListPage(error, req, res) {
    const postsViewModel = {..., error};


};
```
We allow errors to be injected into our home route and propagete them to
views/home.hbs
```html
{{#if error}}
    <h2 class="post-submission-error">{{error}}</h2>
{{/if}}
```

And now we can combine all of this in app.js
```javascript
const renderListPage = home(posts);

app.get('/', (req, res) => renderListPage(null, req, res));
app.post('/post', isAuthenticated, addPost({posts, renderListPage}));
```

## XSS strikes back - context aware encoding [context_aware_encoding]

Many people assume that once they use {{}} in a template engine we're safe.


Add the following post:
```javascript:alert(1)```
And try to click on click me link below.

It turns our that most template engines can only encode HTML content by default.
But if you put user generated content into CSS, JS, URLs, HTML attributes or base64
you have to use context aware encoding. Every <script> or <style> tag is a different
execution context with it's own context specific rules and encodings.

Let's see a test describing this problem: 'Context aware XSS'

We need to enhance handlebars with link encoding.

output/encodeURL.js
```javascript
const ESAPI = require('node-esapi');

function addURLEncoding(hbs) {
    hbs.registerHelper('link', function (value, options) {
        return ESAPI.encoder().encodeForURL(value);
    });
}

module.exports = addURLEncoding;
```
We created a link helper for our template engine to encode all URLs.
Please note that ESAPI provides other contextual methods like:
encodeForHTML,encodeForCSS,encodeForJS,encodeForHTMLAttribute,encodeForBase64

Now let's apply our new helper

views/home.hbs
```
<a href="{{ link posts.[0] }}">Click me</a>
```

And add it to app.js
```javascript
require('./output/encodeURL')(hbs);
```

To summarize then encoding part remember to store use content in the raw format
and encode it at rendering time depending on context.

## Cross Site Request Forgery (CSRF/XSRF) [csrf]

Let's simulate CSRF attack.

We'll run another website from the attacker directory.

```
node attacker/server.js
```

Start our website (localhost:3000) and log in as a genuine user.

Now go to localhost:3001 and open 'Basic CSRF' link and submit a form.
Attacker embedded a form to our genuine website on its website.

To see a more subtle attack that requires nothing by opening a link go to
a 'Script CSRF' link. This time JS submits the form with no user action.
But it's still evident that the attack happened because we're being redirected
to the genuine page.

Go to the 'Iframe CSRF' link now and see how we can make it invisible to the
victim that we've just run the attack.

## CSRF protection with token [csrf_token]

Let those two tests guide our implementation:
'CSRF token generation', 'Reject requests without CSRF token'.

We want CSRF token to be added to the POST submission form.
app.js
```javascript
const csrf = require('csurf')();

app.get('/', csrf, (req, res) => renderListPage(null, req, res));
```
We need to import CSRF token generation middleware.
It will enhance request object with the token generation capability.

Now we can add a token to our view model.

routes/home.js
```javascript
const postsViewModel = {posts: postsList.map(p => p.text), csrfToken: req.csrfToken()};
```

Finally let's propagete csrfToken to our template

views/home.hbs
```html
<input type="hidden" name="_csrf" value="{{csrfToken}}">
```

At this point 'CSRF token generation' should go green.

Now back to app.js
```
app.post('/post', isAuthenticated, csrf, addPost({posts, renderListPage}));
```
Same csrf middleware applied to POST requests will check if CSRF token
is valid.
This should be enough to make 'Reject requests without CSRF token' green.

Check all other tests. Fix broken tests.
Hint:
```javascript
const {cookies, csrfToken} = await userWithCSRFToken();

await post({cookies, csrfToken, msg});
```
For now we can skip 'Basic register/login/post/read posts flow happy path for SPA'.
We'll fix it later.

## CSRF protection in JWT tokens [csrf_jwt_token]

Sometimes we want to make multiple requests without obtaining a new CSRF token
each time.

Here's a golden standard for CSRF protection when using JWT:
![JWT with CSRF protection](https://camo.githubusercontent.com/c68cd231dad57775ee087d9c4568ad6127a834ea/68747470733a2f2f692e696d6775722e636f6d2f4c55695a5146692e6a70673f32)

You may find more information [here](https://www.youtube.com/watch?v=67mezK3NzpU)

What we need to do is to add CSRF token inside JWT token and send the CSRF
token in the HTTP header.

server.js
```javascript
const uuid = require('uuid/v4');

const app = await initApp({uuid});
```
We're injecting uuid from the outside so that we can mock it out in tests.

app.js
```javascript
module.exports = async function initApp({uuid}) {
    ...
    app.post('/login', limiter(), login({users, uuid, jwtSecret: JWT_SECRET, cookieOptions: COOKIE_OPTIONS}));
    ...
}
```
We're passing uuid to the actual location where it's needed.

routes/login.js
```javascript
const login = ({users, uuid, jwtSecret, cookieOptions}) => async (req, res) => {
    ...
    const csrf = uuid();
    const token = jwt.sign({username, 'csrf-token': csrf}, jwtSecret, {expiresIn: '1h'});
    res.set('csrf-token', csrf);
    ...
}
```
Here's the gist of the JWT CSRF token generation.
We're generating random CSRF token and put it both inside JWT and in a header.

middleware/checkCsrf.js
```javascript
const {BAD_REQUEST} = require('../statusCodes');

const checker = csrf => function checkCsrf(req, res, next) {
    if (req.user && req.header('csrf-token')) {
        if (req.user['csrf-token'] === req.header('csrf-token')) {
            next();
        } else {
            res.status(BAD_REQUEST).send("Only authenticated users can post");
        }
    } else {
        return csrf(req, res, next);
    }
};

module.exports = checker;
```
Our enhances CSRF checker for POST requests is now enhanced
with csrf-token header checking.

app.js
```javascript
const csrf = require('csurf')();
const checkCsrf = require('./middleware/checkCsrf')(csrf);

app.post('/post', isAuthenticated, checkCsrf, addPost({posts, renderListPage}));
```
Please note that checkCsrf is after isAuthenticated middleware which
sets req.user.

Check all 'Secure JWT token against CSRF' tests.

Once those tests pass we can fix one of our previous tests for SPA flow:
```javascript
    it('Basic register/login/post/read posts flow happy path for SPA', async function () {
        const {cookies, csrfToken} = await userJSON(DEFAULT_USER_CREDENTIALS);
        const {jwt} = cookies;
        const {header: {location}} = await postJSON({
            cookies: {jwt},
            csrfToken,
            msg: 'test post'
        }).expect(302);
        const listPostsResponse = await getJSON({url: location}).expect(200);

        assert.deepStrictEqual(JSON.parse(listPostsResponse.text).posts, ['test post']);
    });
```