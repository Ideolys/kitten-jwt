const crypto = require('crypto');
const path   = require('path');
const exec   = require('child_process').exec;
const jwa    = require('jwa');
const Qlru   = require('quick-lru');

// default expiration of token in seconds
const DEFAULT_EXPIRE_IN = 60 * 60 * 12;
const ALGORITHM_BITS = '512';
const ALGORITHM_NAME = 'ES'+ALGORITHM_BITS;
const ALGORITHM_SIGN = 'secp521r1'; // 'prime256v1';
const ecdsa          = jwa(ALGORITHM_NAME);

const CLIENT_CACHE_SIZE_MAX = 50;
const clientCache           = new Qlru({maxSize : CLIENT_CACHE_SIZE_MAX});
// how many time before expiration do we renew the token in millisecond
const CLIENT_RENEW_LIMIT    = 60 * 20 * 1000; 


const SERVER_CACHE_SIZE_MAX = 1000;
const serverCache = new Qlru({maxSize : SERVER_CACHE_SIZE_MAX});

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
 */
function parseToken (jwt, callback) {
  let _segments = jwt.split('.');
  if (_segments.length !== 3) {
    return callback(new Error('Invalid JSON Web Token: Not enough or too many segments'));
  }
  let _headerBase64  = _segments[0];
  let _payloadBase64 = _segments[1];
  let _signature     = _segments[2];
  let _tokenString   = _headerBase64 + '.' + _payloadBase64;

  try {
    let _headerString  = base64urlDecode(_headerBase64);
    let _payloadString = base64urlDecode(_payloadBase64);
    let _header        = JSON.parse(_headerString);
    let _payload       = JSON.parse(_payloadString);

    if (!(_payload instanceof Object)) {
      return callback(new Error('Invalid Payload JSON Web token. It is not an object'));
    }

    if (!(_header instanceof Object)) {
      return callback(new Error('Invalid Header JSON Web Token. It is not an object'));
    }

    if (_header.alg !== ALGORITHM_NAME) {
      return callback(new Error('Algorithm not accepted for JSON Web Token. Only ' + ALGORITHM_NAME + ' is accepted'));
    }

    if (_payload.exp && Date.now() > parseInt(_payload.exp, 10) * 1000) {
      return callback(new Error('JSON Web Token expired'));
    }

    if (_payload.iss === '' || _payload.iss === undefined || _payload.iss === null) {
      return callback(new Error('JSON Web Token without issuer'));
    }
    return callback(null, _payload, _tokenString, _signature);
  }
  catch (e) {
    return callback(new Error('Invalid JSON Web Token ' + e.toString()));
  }
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
    return callback(new Error('Invalid JSON Web Token' + e.toString()));
  }
  return callback(null, payload);
}

/**
 * Verify the token
 * 
 * @param  {String}   jwt       base64 token
 * @param  {String}   publicKey public key
 * @param  {Function} callback(err, parsedPayload)
 */
function verify (jwt, publicKey, callback) {
  parseToken(jwt, (err, payload, tokenString, signature) => {
    if (err) {
      return callback(err);
    }
    return verifyToken(payload, tokenString, signature, publicKey, callback);
  });
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
  if ( _cachedToken !== undefined && _now < (_cachedToken.expireAt - CLIENT_RENEW_LIMIT) && _cachedToken.privKey === privKey ) {
    return _cachedToken.token;
  }
  let _newToken = generate(clientId, serverId, DEFAULT_EXPIRE_IN, privKey, data);

  clientCache.set(_cacheKey, {
    token    : _newToken,
    privKey  : privKey,
    expireAt : _now + (DEFAULT_EXPIRE_IN * 1000)
  });

  return _newToken;
}

function _assertKeys (keys, payload, tokenString, signature, token, callback, i = 0) {
  const _assertKey = (key, callback) => {
    verifyToken(payload, tokenString, signature, key, (err) => {
      serverCache.set(token, { payload: payload, err: err });
      if (err) {
        return callback(err);
      }
      callback(null);
    });
  }
  _assertKey(keys[i], err => {
    if (err) {
      if (i === keys.length - 1) {
        return callback(new Error('Invalid JSON Web Token signature'));
      }
      return _assertKeys(keys, payload, tokenString, signature, token, callback, i + 1);
    }
    callback();
  });
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
    if (!req.headers) {
      return next(new Error('JSON Web Token - No HTTP header detected'));
    }
    let _auth = req.headers.Authorization || req.headers.authorization;
    if (typeof _auth !== 'string') {
      return next(new Error('No Authorization HTTP header detected. Format is "Authorization: Bearer jwt"'));
    }
    if (/^Bearer /i.test(_auth) === false) {
      return next(new Error('No Bearer JSON Web Token detected. Format is "Authorization: Bearer jwt"'));
    }
    let _token = _auth.slice(7);

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
        if (publicKey.constructor !== Array) {
          publicKey = [publicKey];
        }
        _assertKeys(publicKey, payload, tokenString, signature,_token, err => {
          if (err) {
            return next(err);
          }
          req.jwtPayload = payload;
          next();
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
  verify,
  verifyHTTPHeaderFn,
  generate,
  getToken,
  resetCache,
  generateECDHKeys,
  generateAuto : getToken // deprecated
};

