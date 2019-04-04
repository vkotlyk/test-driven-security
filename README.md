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