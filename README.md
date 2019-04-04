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

## Setting the context

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
