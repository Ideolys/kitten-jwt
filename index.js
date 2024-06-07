const path   = require('path');
const exec   = require('child_process').exec;
const jwa    = require('jwa');
const cache  = require('kitten-cache');

const DEFAULT_ALGORITHM_BITS = '512';
const DEFAULT_ALGORITHM_NAME = 'ES' + DEFAULT_ALGORITHM_BITS;
const DEFAULT_ALGORITHM_SIGN = 'secp521r1'; // 'prime256v1';
const ALLOWED_ALGORITHMS     = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512'];

const TOKEN_COOKIE_REGEXP = /access_token\s*=([^;]+?)(?:;|$)/;

const params = {
  // client cache size used by getToken
  clientCacheSize                        : 255,
  // how many time before expiration do we renew the token in millisecond
  clientRenewTokenBeforeExp              : 60 * 20 * 1000,
  // default expiration of token in seconds
  clientTokenExpiration                  : 60 * 60 * 12,
  // server cache size used by verifyHTTPHeaderFn
  serverCacheSize                        : 255,
  // Invalidate bad token cache after XX milliseconds when the error is coming from getPublicKey
  serverGetPublicKeyErrorCacheExpiration : 120 * 1000
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
  for (const _attr in options) {
    if (params[_attr] !== undefined) {
      params[_attr] = options[_attr];
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
  const _str = str.replace(/-/g, '+').replace(/_/g, '/');
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
  const _filepath = path.join(outputDir, outputKeyName);
  const _cmdline  = `openssl ecparam -name ${DEFAULT_ALGORITHM_SIGN} -out ${_filepath}-temp.pem && openssl ecparam -in ${_filepath}-temp.pem -genkey -noout -out ${_filepath}.pem && openssl ec -in ${_filepath}.pem -pubout -out ${_filepath}.pub && rm ${_filepath}-temp.pem`;
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
 * @param {{
 *  header : {
 *    alg : String,
 *    typ : String,
 *    kid : String
 *  },
 *  payload : {
 *    clientId  : Mixed,
 *    serverId  : Mixed,
 *    expiresIn : Integer  // in seconds
 *  },
 *  privKey   : String     //private key
 * }} options 
 *    
 * @param   {Mixed}   data 
 * @returns {String}  return the token
 */
function generate (options, data) {
  const _now = Math.floor(Date.now() / 1000);
  const _header = {
    alg : options?.header?.alg || DEFAULT_ALGORITHM_NAME,
    typ : options?.header?.typ || 'JWT',
    ...(options?.header?.kid) && { kid : options.header.kid },
  };

  // generate a compact token must be compact
  const _payloadObject = Object.assign({
    iss : options.payload.clientId,
    aud : options.payload.serverId,
    exp : (_now + options.payload.expiresIn)
  }, options.payload);
  
  // deletion of already assigned keys to avoid duplication
  const {
    clientId,
    serverId,
    expiresIn, 
    ... _payload 
  } = _payloadObject;

  if (data) {
    _payload.data = data;
  }
  
  const _tokenString = base64urlEncode(JSON.stringify(_header))+'.'+base64urlEncode(JSON.stringify(_payload));
  const _signature   = jwa(options?.header?.alg || DEFAULT_ALGORITHM_NAME).sign(_tokenString, options.privKey);
  // I should be able to use only nodejs, but there is something which does not follow RFCs
  // let _signature = crypto.createSign('SHA'+ALGORITHM_HASH).update(_tokenString).sign(privKey, 'base64');
  // let _signature64 = formatEcdsa.joseToDer(base64urlEncode(_signature), 'ES' + ALGORITHM_HASH);
  const _tokenBase64WithSignature = _tokenString + '.' + _signature;

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
  const _segments = jwt.split('.');
  if (_segments.length !== 3) {
    return callback(new Error('Invalid JSON Web Token: Not enough or too many segments'));
  }
  const _headerBase64  = _segments[0];
  const _payloadBase64 = _segments[1];
  const _signature     = _segments[2];
  const _tokenString   = _headerBase64 + '.' + _payloadBase64;
  let _header          = null;
  let _payload         = null;

  try {
    const _headerString  = base64urlDecode(_headerBase64);
    const _payloadString = base64urlDecode(_payloadBase64);
    _header              = JSON.parse(_headerString);
    _payload             = JSON.parse(_payloadString);
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

  if (!ALLOWED_ALGORITHMS.includes(_header.alg)) {
    return callback(new Error(`Algorithm not accepted for JSON Web Token. Only ${ALLOWED_ALGORITHMS.join(', ')} are accepted`));
  }

  if (_payload.exp && now > parseInt(_payload.exp, 10) * 1000) {
    return callback(new Error('JSON Web Token expired'), _header, _payload);
  }

  if (_payload.iss === '' || _payload.iss === undefined || _payload.iss === null) {
    return callback(new Error('JSON Web Token without issuer'));
  }

  return callback(null, _header, _payload, _tokenString, _signature);
}

/**
 * Verify the token
 * 
 * @param  {Object}   header      parsed token by parseToken
 * @param  {Object}   payload     parsed token by parseToken
 * @param  {[type]}   tokenString token base64 string
 * @param  {[type]}   signature   signature only
 * @param  {[type]}   publicKey   public key
 * @param  {Function} callback(err, parsedPayload)
 */
function verifyToken (header, payload, tokenString, signature, publicKey, callback) {
  try {
    const _isValidSignature = jwa(header?.alg || DEFAULT_ALGORITHM_NAME).verify(tokenString, signature, publicKey);
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
  parseToken(jwt, (err, header, payload, tokenString, signature) => {
    if (err) {
      return callback(err, payload);
    }

    return verifyToken(header, payload, tokenString, signature, publicKey, callback);
  }, now);
}

/**
 * Generate, use and renew the token automatically
 * 
 * @param {{
 *  header : {
 *    alg : String,
 *    typ : String,
 *    kid : String
 *  },
 *  payload : {
 *    clientId  : Mixed,
 *    serverId  : Mixed
 *  },
 *  privKey   : String //private key
 * }} options 
 *    
 * @param   {Object}  data user data
 * @returns {String}  return the token
 */
function getToken (options, data) {
  const _cacheKey    = options.payload.clientId + '_' + options.payload.serverId;
  const _cachedToken = clientCache.get(_cacheKey);
  const _now         = Date.now();
  if ( 
    _cachedToken !== undefined 
      && _now < (_cachedToken.expireAt - params.clientRenewTokenBeforeExp) 
        && _cachedToken.privKey === options.privKey 
  ) {
    return _cachedToken.token;
  }

  const optionForTokenGeneration = {
    ... options,
    payload : {
      ... options.payload,
      expiresIn : params.clientTokenExpiration
    }
  };
  const _newToken = generate(optionForTokenGeneration, data);

  clientCache.set(_cacheKey, {
    token    : _newToken,
    privKey  : options.privKey,
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
function verifyTokenForEachPublicKey (publicKeys, header, payload, tokenString, signature, callback, i = 0) {
  verifyToken(header, payload, tokenString, signature, publicKeys[i], (err) => {
    i++;
    if (!err || i >= publicKeys.length) {
      return callback(err);
    }
    // avoid looping without releasing NodeJS event loop
    process.nextTick(() => {
      verifyTokenForEachPublicKey(publicKeys, header, payload, tokenString, signature, callback, i);
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
  const _token = req.headers.authorization || req.headers.Authorization || parseCookie(req.headers.cookie);

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
  const _token = TOKEN_COOKIE_REGEXP.exec(cookie);
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
      const _now = Date.now();

      // is it in cache, fast return of errors or not
      const _cachedToken = serverCache.get(_token);
      if (_cachedToken && (_cachedToken.expireAt === 0 || _cachedToken.expireAt > _now)) {
        if (_cachedToken.payload !== undefined && _cachedToken.payload.exp !== undefined && _now > parseInt(_cachedToken.payload.exp, 10) * 1000) {
          _cachedToken.err = new Error('JSON Web Token expired');
        }
        if (_cachedToken.err) {
          return next(_cachedToken.err);
        }
        req.jwtPayload = _cachedToken.payload;
        return next();
      }

      // otherwise, compute everything
      parseToken(_token, (err, header, payload, tokenString, signature) => {
        if (err) {
          serverCache.set(_token, { payload : payload, err : err, expireAt : 0 });
          return next(err);
        }
        if (payload && payload.aud !== serverId) {
          const _err = new Error('Invalid JSON Web Token audience');
          serverCache.set(_token, { payload : payload, err : _err, expireAt : 0 });
          return next(_err);
        }
        getPublicKeyFn(req, res, payload, function (errPublicKey, publicKey) {
          const _publicKeys = (publicKey instanceof Array) ? publicKey : [publicKey];
          if (errPublicKey || !publicKey || _publicKeys.length === 0) {
            // If we cannot get the public key, store this error in cache with an expiration date
            const _err = new Error('Empty public key or no public key available');
            serverCache.set(_token, { payload : payload, err : _err, expireAt : (_now + params.serverGetPublicKeyErrorCacheExpiration) });
            return next(_err);
          }
          verifyTokenForEachPublicKey(_publicKeys, header, payload, tokenString, signature, (err) => {
            // what ever happens, put result in cache
            serverCache.set(_token, { payload : payload, err : err, expireAt : 0 });
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
