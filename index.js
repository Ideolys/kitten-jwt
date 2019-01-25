const crypto = require('crypto');
const path   = require('path');
const exec   = require('child_process').exec;
const jwa    = require('jwa');

// default expiration of token in seconds
const DEFAULT_EXPIRE_IN = 60 * 60 * 12;
const ALGORITHM_BITS = '512';
const ALGORITHM_NAME = 'ES'+ALGORITHM_BITS;
const ALGORITHM_SIGN = 'secp521r1'; // 'prime256v1';
const ecdsa          = jwa(ALGORITHM_NAME);

const clientCacheKey        = new Map();
const CLIENT_CACHE_SIZE_MAX = 50;
// how many time before expiration do we renew the token in millisecond
const CLIENT_RENEW_LIMIT    = 60 * 20 * 1000; 

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
 * @param  {Integer} expiresIn
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
    return callback(new Error('Not enough or too many segments'));
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
      return callback(new Error('Payload is not an object'));
    }

    if (!(_header instanceof Object)) {
      return callback(new Error('Header is not an object'));
    }

    if (_header.alg !== ALGORITHM_NAME) {
      return callback(new Error('Algorithm not accepted'));
    }

    if (_payload.exp && Date.now() > parseInt(_payload.exp, 10) * 1000) {
      return callback(new Error('Token expired'));
    }

    if (_payload.iss === '' || _payload.iss === undefined || _payload.iss === null) {
      return callback(new Error('Token without issuer'));
    }
    return callback(null, _payload, _tokenString, _signature);
  }
  catch (e) {
    return callback(new Error('Invalid token ' + e.toString()));
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
      return callback(new Error('Invalid token signature'));
    }

  } catch (e) {
    return callback(new Error('Invalid token' + e.toString()));
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
 */
function getToken (clientId, serverId, privKey) {
  let _cacheKey = clientId + '_' + serverId;

  let _cachedToken = clientCacheKey.get(_cacheKey);
  let _now = Date.now();
  if ( _cachedToken !== undefined && _now < (_cachedToken.expireAt - CLIENT_RENEW_LIMIT) && _cachedToken.privKey === privKey ) {
    return _cachedToken.token;
  }
  let _newToken = generate(clientId, serverId, DEFAULT_EXPIRE_IN, privKey);

  // protection against infinite growth (TODO, become LRU)
  if (clientCacheKey.length > CLIENT_CACHE_SIZE_MAX) {
    clientCacheKey.clear();
  }

  clientCacheKey.set(_cacheKey, {
    token    : _newToken,
    privKey  : privKey,
    expireAt : _now + (DEFAULT_EXPIRE_IN * 1000)
  });

  return _newToken;
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
      return next(new Error('No header detected'));
    }
    let _auth = req.headers.Authorization || req.headers.authorization;
    if (typeof _auth !== 'string') {
      return next(new Error('No Authorization HTTP header detected. Format is "Authorization: Bearer token"'));
    }
    if (/^Bearer /i.test(_auth) === false) {
      return next(new Error('No Bearer Token detected. Format is "Authorization: Bearer token"'));
    }
    let _token = _auth.slice(7);

    parseToken(_token, (err, payload, tokenString, signature) => {
      if (err) {
        return next(err);
      }
      if (payload && payload.aud !== serverId) {
        return next(new Error('Invalid token audience'));
      }
      getPublicKeyFn(req, res, payload, function (publicKey) {
        verifyToken(payload, tokenString, signature, publicKey, (err) => {
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
  clientCacheKey.clear();
}

module.exports = {
  verify             : verify,
  verifyHTTPHeaderFn : verifyHTTPHeaderFn,
  generate           : generate,
  generateAuto       : getToken, // deprecated
  getToken           : getToken,
  getToken           : getToken,
  resetCache         : resetCache,
  generateECDHKeys   : generateECDHKeys
};

