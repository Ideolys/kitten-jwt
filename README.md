# Kitten JWT

Keep It Simple, Stupid, Secure and Fast JWT module

## Philosophy and why

- Keep it Simple Stupid
- Performance & Security focused
- Light, low dependency

Most of the time, people uses node-jsonwebtoken and express-jwt without using a cache mechanism 
to verify tokens. This requires a lot of CPU for each request on server-side! 
On client-side, the token is generated once with an infinite expiration timestamp, which is not very secure.
The first purpose of this module is to solve these two problems.

When discovering JWT, you do not know what signing algorithm to choose and where to put your data (issuer, audience, ...).
This module solves this for you. It chooses a highly secured algorithm by default. If you want another algorithm, fork it.
The algorithm used (asymmetric) allow the client to generate himself a token without having to exchange a secret with the server.
Only the public key is exchanged.

To save extra bandwidth, it let you define only two parameters : a client id ("Alice", issuer), and a server id ("Bob", audience).
The generated token allows only Alice (clientId) to speak exclusively to Bob (serverId).

Main purpose : be plug'n'play for developers who do not have a lot of time.

## Features

- Follows JWT RFC
- Ultra-fast JWT generator with automatic renewal every 12-hours for client side: 1 Million per second
- Ultra-fast JWT verification using LRU-cache for server side: 0.5 Million per second
- Fastify, Restify or Express authentication middleware
- Highly secured by default with asymmetric ECDSA keys (ES512)
- ECDSA Public / Private key generator

## Installation

```js
  npm install kitten-jwt --save
```

## Getting started

#### 1) On client-side

Using `request` module for example:

```js
  var jwt = require('kitten-jwt');

  // Generate an ephemeral jwt token (short expiration date), auto-renewed every 12-hour by default
  // This function is very fast (uses cache), it can be called for every HTTP request
  var token = jwt.getToken('client-id-1220202', 'server-app-name', 'privKeyOfTheClient');

  // Insert the token in HTTP Header, it will be parsed by jwt.verifyHTTPHeaderFn automatically
  request.setHeader('Authorization', 'Bearer ' + token); // "Bearer" keyword is optional

```

Or, if your client is a browser, store the JWT in a `cookie` instead of `Authorization` header.
With `ExpressJS`:

```js
  // let the browser send it back automatically. 
  // Do not forget to refresh it before the 12-hour expiration
  response.cookie('access_token', token);
```

#### 2) On server-side 

```js
  var jwt = require('kitten-jwt');

  // custom method to get the client public key, kitten-jwt caches the result automatically
  function getPublicKeyFn(req, res, payload, callback) {
    var _clientId = payload.iss;
    // do whatever you want: db query, file read to return the public key
    // it accepts an array of public key ['pubKeyOfTheClient1', 'pubKeyOfTheClient2']
    return callback('pubKeyOfTheClient');
  }

  // use the helper function to verify token in an express middleware
  // This function is very fast (uses lru-cache)
  // It searches JWT in req.header.authorization, then in req.header.cookie.<access_token>
  express().use(jwt.verifyHTTPHeaderFn('server-app-name', getPublicKeyFn));

  // if the public key changes
  jwt.resetCache();

  // In other middleware, you can print JWT payload object, added by verifyHTTPHeaderFn
  console.log(req.jwtPayload);
```


## API Usage

Token generated by kitten-jwt are quite compact (limited) for performance reasons, and follows JWT RFC

- header

```js
  {
    alg : 'ES512',
    typ : JWT
  }
```

- payload

```js
  {
    iss  : clientId,                  // issuer
    aud  : serverId,                  // audience, tenand id, etc...
    exp  : (Date.now() + expiresIn)   // expiration timestamp UTC
  }
```

Why it is important to have a serverId? If the audience is not defined, the same token
can be used for another web-service which have the same clientId and public key.


### High-level API

These functions uses cache to be as fast as possible

* `jwt.getToken (clientId, serverId, privKey)`

  Generate a token for the tuple clientId-serverId, which expires in about 12 hours (+- random)<br>
  Re-use this same token during about 12 hours if called more than twice<br>
  Generate a new token automatically before expiration (20-minute before) or if privKey change

  - clientId  : JWT issuer, token.iss
  - serverId  : JWT audience, token.aud
  - privKey   : private key

* `jwt.verifyHTTPHeaderFn (serverId, getPublicKeyFn)`

  Generate a middleware `function(req, req, next)`<br>
  Verify and set `req.jwtPayload`

  - getPublicKeyFn    : Function(req, res, payload, callback) which must call the `callback(String|Array)` where 
                        the parameter is either a string (one public key) or an array of strings (multiple public key to test)
  - serverId          : JWT audience, token.aud
  if the token is invalid, next(err) is called. Thus you can catch the error in another 4-parameter middlewares.

* `jwt.resetCache (clientId, callback)` : invalidate cache


### Low-level API

These APIs should **not be used directly in a web app because nothing is cached (slow)**.

* `jwt.generate (clientId, serverId, expiresIn, privKey, data)` : generate a token

  - clientId  : JWT issuer, token.iss
  - serverId  : JWT audience, token.aud
  - expiresIn : JWT duration in number of seconds
  - privKey   : private key
  - data      : accessible in token.data

  It returns a signed base64 url encoded string of the token.

* `jwt.verify (jwt, pubKey, callback, now = Date.now())` : verify the signature of a token

  - jwt                     : JSON Web token string to verify
  - pubKey                  : public key
  - callback (err, payload) : callback, payload is an object
  - now                     : current timestamp used to check if the token is expired

* `jwt.generateECDHKeys (outputDir, outputKeyName, callback)` : generate pub / priv ECDSA keys

* `jwt.set (options)` : set default options:
  ```js
  {
    // client cache size used by getToken
    clientCacheSize : 5,
    // how many time before client token expiration kitten-cache renews tokens in millisecond
    clientRenewTokenBeforeExp : 60 * 20 * 1000,
    // default client tokens expiration in seconds
    clientTokenExpiration : 60 * 60 * 12,
    // server cache size used by verifyHTTPHeaderFn
    serverCacheSize : 5
  }
  ```


## CHANGELOG

**1.1.1**
- `verify` returns payload even if the token is expired

**1.1.0**
- replace quick-lru by kitten-cache (faster, lower memory consumption)
- change default cache size with new function `set(options)`
- WARNING: reduce server/client cache size to 5 by default to reduce memory consumption
- set current timestamp in `verify` function

**1.0.0**

- Possibility to verify a token with multiple public keys. `getPublicKeyFn` can return an array of public keys
- Increase key cache to 200
- Improve error output
- Accepts token in cookie `access_token`
- Accepts token without key word "Bearer"


## Notes 

TODO :

- to save extra bandwidth:  kitten-jwt accepts and generate tokens with one-letter header instead of RFCs JWT header (optional)
- make expiration a little bit random
- should i use https://en.wikipedia.org/wiki/Curve25519 ?
https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf
https://www.npmjs.com/package/sodium
https://github.com/volschin/node-curve25519
https://ianix.com/pub/curve25519-deployment.html