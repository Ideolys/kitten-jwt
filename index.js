const path   = require('path');
const exec   = require('child_process').exec;
const jwa    = require('jwa');
const cache  = require('kitten-cache');

const ALGORITHM_BITS = '512';
const ALGORITHM_NAME = 'ES'+ALGORITHM_BITS;
const ALGORITHM_SIGN = 'secp521r1'; // 'prime256v1';
const ecdsa          = jwa(ALGORITHM_NAME);

const TOKEN_COOKIE_REGEXP = /access_token\s*=([^;]+?)(?:;|$)/;

let params = {
  // client cache size used by getToken
  clientCacheSize : 5,
  // how many time before expiration do we renew the token in millisecond
  clientRenewTokenBeforeExp : 60 * 20 * 1000,
  // default expiration of token in seconds
  clientTokenExpiration : 60 * 60 * 12,
  // server cache size used by verifyHTTPHeaderFn
  serverCacheSize : 5
};

let clientCache = new cache({size : params.clientCacheSize});
let serverCache = new cache({size : params.serverCacheSize});


/**
 * Sets options
 *
 * @param  {Object}   options : {
 *                                // client cache size used by getToken
 *                                clientCacheSize : 5,
 *                                // how many time before token expiration do we renew the token in millisecond
 *                                clientRenewTokenBeforeExp : 60 * 20 * 1000,
 *                                // default expiration of token in seconds
 *                                clientTokenExpiration : 60 * 60 * 12,
 *                                // server cache size used by verifyHTTPHeaderFn
 *                                serverCacheSize : 5
 *                              }
 */
function set (options) {
  for(let _attr in options) {
    if (params[_attr] !== undefined) {
      params[_attr] = options[_attr]
    }
  }
  // reset cache only if clientCacheSize or serverCacheSize changes
  if (options.clientCacheSize || options.serverCacheSize) {
    clientCache = new cache({size : params.clientCacheSize});
    serverCache = new cache({size : params.serverCacheSize});
  }
}

/**
 * Decode base64 url if there is in the token
 * 
 * @param  {String} str
 * @return {String}
 */
function base64urlDecode (str) {
  let _str = str.replace(/\-/g, '+').replace(/_/g, '/');
  return Buffer
    .from(_str, 'base64')
    .toString('utf8');
}

/**
 * Base64 url if there is in the token
 * 
 * @param  {String} str
 * @return {String}
 */
function base64urlEncode (str) {
  return Buffer
    .from(str, 'utf8')
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/**
 * Generate ECDH pub / priv keys
 * 
 * @param  {[type]}   outputDir     directory where to write keys
 * @param  {[type]}   outputKeyName key name
 * @param  {Function} callback(err, stderr, stdout)      
 */
function generateECDHKeys (outputDir, outputKeyName, callback) {
  let _filepath = path.join(outputDir, outputKeyName);
  let _cmdline  = `openssl ecparam -name ${ALGORITHM_SIGN} -out ${_filepath}-temp.pem && openssl ecparam -in ${_filepath}-temp.pem -genkey -noout -out ${_filepath}.pem && openssl ec -in ${_filepath}.pem -pubout -out ${_filepath}.pub && rm ${_filepath}-temp.pem`;
  exec(_cmdline, function (err, stdout, stderr) {
    if (err) {
      console.log('WARNING: cannot generate ECDH keys:' + err);
    }
    callback(err, stderr, stdout);
  });
}

/**
 * Generate a token
 * 
 * @param  {Mixed}   clientId
 * @param  {Mixed}   serverId
 * @param  {Integer} expiresIn in seconds
 * @param  {String}  privKey
 * @param  {Mixed}   data
 * @return {String}  return the token
 */
function generate (clientId, serverId, expiresIn, privKey, data) {
  let _now = Math.floor(Date.now() / 1000);
  
  let _header = {
    alg : ALGORITHM_NAME,
    typ : 'JWT'
  };
  // generate a compact token must be compact
  let _token = {
    iss : clientId,
    aud : serverId,
    exp : (_now + expiresIn)
  };

  if (data) {
    _token.data = data;
  }

  let _tokenString = base64urlEncode(JSON.stringify(_header))+'.'+base64urlEncode(JSON.stringify(_token));
  let _signature   = ecdsa.sign(_tokenString, privKey);
  // I should be able to use only nodejs, but there is something which does not follow RFCs
  // let _signature = crypto.createSign('SHA'+ALGORITHM_HASH).update(_tokenString).sign(privKey, 'base64');
  // let _signature64 = formatEcdsa.joseToDer(base64urlEncode(_signature), 'ES' + ALGORITHM_HASH);
  let _tokenBase64WithSignature = _tokenString + '.' + _signature;

  return _tokenBase64WithSignature;
}

/**
 * Parse token
 * 
 * @param  {String}   jwt      base64 token
 * @param  {Function} callback(err, parsedPayload)
 * @param  {Integer}  now      Current timestamp in ms
 */
function parseToken (jwt, callback, now = Date.now()) {
  let _segments = jwt.split('.');
  if (_segments.length !== 3) {
    return callback(new Error('Invalid JSON Web Token: Not enough or too many segments'));
  }
  let _headerBase64  = _segments[0];
  let _payloadBase64 = _segments[1];
  let _signature     = _segments[2];
  let _tokenString   = _headerBase64 + '.' + _payloadBase64;
  let _header        = null;
  let _payload       = null;

  try {
    let _headerString  = base64urlDecode(_headerBase64);
    let _payloadString = base64urlDecode(_payloadBase64);
    _header            = JSON.parse(_headerString);
    _payload           = JSON.parse(_payloadString);
  }
  catch (e) {
    return callback(new Error('Invalid JSON Web Token: ' + e.message));
  }

  if (!(_payload instanceof Object)) {
    return callback(new Error('Invalid Payload JSON Web token. It is not an object'));
  }

  if (!(_header instanceof Object)) {
    return callback(new Error('Invalid Header JSON Web Token. It is not an object'));
  }

  if (_header.alg !== ALGORITHM_NAME) {
    return callback(new Error('Algorithm not accepted for JSON Web Token. Only ' + ALGORITHM_NAME + ' is accepted'));
  }

  if (_payload.exp && now > parseInt(_payload.exp, 10) * 1000) {
    return callback(new Error('JSON Web Token expired'));
  }

  if (_payload.iss === '' || _payload.iss === undefined || _payload.iss === null) {
    return callback(new Error('JSON Web Token without issuer'));
  }
  return callback(null, _payload, _tokenString, _signature);
}

/**
 * Verify the token
 * 
 * @param  {Object}   payload     parsed token by parseToken
 * @param  {[type]}   tokenString token base64 string
 * @param  {[type]}   signature   signature only
 * @param  {[type]}   publicKey   public key
 * @param  {Function} callback(err, parsedPayload)
 */
function verifyToken (payload, tokenString, signature, publicKey, callback) {
  try {
    let _isValidSignature = ecdsa.verify(tokenString, signature, publicKey);
    // let _verifier = crypto.createVerify('RSA-SHA'+ALGORITHM_HASH).update(tokenString);
    // let _isValidSignature = _verifier.verify(publicKey, signature, 'base64');

    if (_isValidSignature === false) {
      return callback(new Error('Invalid JSON Web Token signature'));
    }

  } catch (e) {
    return callback(new Error('Invalid JSON Web Token: ' + e.message));
  }
  return callback(null, payload);
}

/**
 * Verify the token
 * 
 * @param  {String}   jwt       base64 token
 * @param  {String}   publicKey public key
 * @param  {Function} callback(err, parsedPayload)
 * @param  {Integer}  now       Current timestamp in ms
 */
function verify (jwt, publicKey, callback, now = Date.now()) {
  parseToken(jwt, (err, payload, tokenString, signature) => {
    if (err) {
      return callback(err);
    }
    return verifyToken(payload, tokenString, signature, publicKey, callback);
  }, now);
}

/**
 * Generate, use and renew the token automatically
 * 
 * @param  {Mixed}  clientId client id 
 * @param  {Mixed}  serverId server id
 * @param  {String} privKey  private key
 * @param  {Object} data     user data
 */
function getToken (clientId, serverId, privKey, data) {
  let _cacheKey = clientId + '_' + serverId;

  let _cachedToken = clientCache.get(_cacheKey);
  let _now = Date.now();
  if ( _cachedToken !== undefined && _now < (_cachedToken.expireAt - params.clientRenewTokenBeforeExp) && _cachedToken.privKey === privKey ) {
    return _cachedToken.token;
  }
  let _newToken = generate(clientId, serverId, params.clientTokenExpiration, privKey, data);

  clientCache.set(_cacheKey, {
    token    : _newToken,
    privKey  : privKey,
    expireAt : _now + (params.clientTokenExpiration * 1000)
  });

  return _newToken;
}


/**
 * Verify token with a list of public keys
 * 
 * @param  {Array}    publicKeys    array of public keys
 * @param  {Object}   payload     
 * @param  {String}   tokenString
 * @param  {String}   signature
 * @param  {Function} callback(err) 
 * @param  {Number}   i             iterator of public keys
 */
function verifyTokenForEachPublicKey (publicKeys, payload, tokenString, signature, callback, i = 0) {
  verifyToken(payload, tokenString, signature, publicKeys[i], (err) => {
    i++;
    if (!err || i >= publicKeys.length) {
      return callback(err);
    }
    // avoid looping without releasing NodeJS event loop
    process.nextTick(() => {
      verifyTokenForEachPublicKey(publicKeys, payload, tokenString, signature, callback, i);
    });
  });
}

/**
 * Check if a token exists in Authorization header first or in cookies
 * 
 * @param {Object} req Req from request
 * @param {Function} callback(err, oken)
 */
function findToken (req, callback) {
  if (!req.headers) {
    return callback(new Error('JSON Web Token - No HTTP header detected'));
  }
  // Accept tokens in authorization header and cookies
  let _token = req.headers.authorization || req.headers.Authorization || parseCookie(req.headers.cookie);

  if (typeof _token !== 'string' || _token.length === 0) {
    return callback(new Error('No JSON Web Token detected in Authorization header or Cookie. Format is "Authorization: jwt" or "Cookie: access_token=jwt"'));
  }
  // remove Bearer keyword if present
  if (/^Bearer /i.test(_token) === true) {
    return callback(null, _token.slice(7));
  }
  return callback(null, _token);
}

/**
 * Parse cookie to get JWT in access_token key
 * 
 * @param  {String} cookie req.headers.cookie
 * @return {String}        jwt if found, null otherwise
 */ 
function parseCookie (cookie) {
  var _token = TOKEN_COOKIE_REGEXP.exec(cookie);
  if (_token instanceof Array && _token.length > 1) {
    return _token[1].trim();
  }
  return null;
}


/**
 * Generate a middleware for Express
 *
 * @param  {Mixed}  serverId       accepted server id
 * @param  {String} getPublicKeyFn public key of client
 * @return {Function}              with parameters (req, res, next)
 */
function verifyHTTPHeaderFn (serverId, getPublicKeyFn) {
  return function (req, res, next) {
    // Get token in authorization header or cookies
    findToken(req, (err, _token) => {
      if (err) {
        return next(err);
      }

      // is it in cache, fast return of errors or not
      let _cachedToken = serverCache.get(_token);
      if (_cachedToken) {
        if (_cachedToken.payload !== undefined && _cachedToken.payload.exp !== undefined && Date.now() > parseInt(_cachedToken.payload.exp, 10) * 1000) {
          _cachedToken.err = new Error('JSON Web Token expired');
        }
        if (_cachedToken.err) {
          return next(_cachedToken.err);
        }
        req.jwtPayload = _cachedToken.payload;
        return next();
      }

      // otherwise, compute everything
      parseToken(_token, (err, payload, tokenString, signature) => {
        if (err) {
          serverCache.set(_token, { payload : payload, err : err });
          return next(err);
        }
        if (payload && payload.aud !== serverId) {
          let _err = new Error('Invalid JSON Web Token audience');
          serverCache.set(_token, { payload : payload, err : _err });
          return next(_err);
        }
        getPublicKeyFn(req, res, payload, function (publicKey) {
          var _publicKeys = (publicKey instanceof Array) ? publicKey : [publicKey];
          verifyTokenForEachPublicKey(_publicKeys, payload, tokenString, signature, (err) => {
            // what ever happens, put result in cache
            serverCache.set(_token, { payload : payload, err : err });
            if (err) {
              return next(err);
            }
            req.jwtPayload = payload;
            next();
          });
        });
      });
    });
  };
}

/**
 * Reset client cache
 * 
 */
function resetCache () {
  clientCache.clear();
  serverCache.clear();
}

module.exports = {
  set,
  verify,
  verifyHTTPHeaderFn,
  generate,
  getToken,
  resetCache,
  generateECDHKeys,
  parseCookie,
  generateAuto : getToken // deprecated
};

