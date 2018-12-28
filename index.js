const crypto = require('crypto');
const path = require('path');
const exec = require('child_process').exec;

const DEFAULT_EXPIRE_IN = 60 * 60 * 12;

function base64urlDecode (str) {
  var _str = str.replace(/\-/g, '+').replace(/_/g, '/');
  return Buffer
    .from(_str, 'base64')
    .toString('utf8');
}

function base64urlEncode (str) {
  return Buffer
    .from(str, 'utf8')
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/**
 * Generate RSA / DSA public and private keys.
 * Only used with NPM install
 * @return {Object} {pub : 'public key', pem:'private key'}
 */
function generateKeys (outputDir, outputKeyName, callback) {
  var keyLength = 3072;
  var keyPairPath = outputDir;

  // Generate DSA to sign/verify     => DSA can be used only to sign/verify
  var _cmdline = '    openssl dsaparam ' + keyLength + ' < /dev/random > ' + keyPairPath + '/dsaparam.pem' +
    ' && openssl gendsa   -out ' + keyPairPath + '/' + outputKeyName + '.pem ' + keyPairPath + '/dsaparam.pem  ' +
    ' && openssl dsa      -in ' + keyPairPath + '/' + outputKeyName + '.pem -pubout > ' + keyPairPath + '/' + outputKeyName + '.pub' +
    ' && rm ' + keyPairPath + '/dsaparam.pem';
  exec(_cmdline, function (err, stdout, stderr) {
    if (err) {
      console.log('WARNING: cannot generate RSA keys:' + err);
    }
    callback(err, stderr, stdout);
  });
}

/**
 * Generate ECDH pub / priv keys
 * Only used with NPM install
 */
function generateECDHKeys (outputDir, outputKeyName, callback) {
  var _filepath = path.join(outputDir, outputKeyName);
  var _algo     = 'secp521r1';
  var _cmdline  = `openssl ecparam -name ${_algo} -out ${_filepath}-temp.pem && openssl ecparam -in ${_filepath}-temp.pem -genkey -noout -out ${_filepath}.pem && openssl ec -in ${_filepath}.pem -pubout -out ${_filepath}.pub && rm ${_filepath}-temp.pem`;
  ;
  exec(_cmdline, function (err, stdout, stderr) {
    if (err) {
      console.log('WARNING: cannot generate ECDH keys:' + err);
    }
    callback(err, stderr, stdout);
  });
}


/**
 * Compute the digital signature 
 * For security purpose, we must use a different key-pair to sign (encryption use another key-pair)
 * We choose DSA to sign because it faster than RSA
 * @param  {String} privateDSAKey    private DSA key
 * @param  {String} tokenString      stringified token
 * @return {String}                  signature
 */
function computeDigitalSignature (privateDSAKey, tokenString) {
  // Generate a hash of the token
  var _hexHashMsg = crypto.createHash('SHA256').update(tokenString, 'utf8').digest('hex');
  var _hashMsg = new Buffer(_hexHashMsg).toString('base64');
  // generate signature using the private DSA key of Easilys
  var _signature = crypto.createSign('SHA1').update(tokenString + _hashMsg).sign(privateDSAKey, 'base64');
  return _signature;
}


function generate (clientId, serverId, expiresIn, privKey, data) {
  var _now = Math.floor(Date.now() / 1000);
  
  // generate a compact token must be compact
  var _token = {
    iss : clientId,
    aud : serverId,
    exp : (_now + expiresIn)
  };

  if (data) {
    _token.data = data;
  }

  var _tokenString = JSON.stringify(_token);
  var _signature = crypto.createSign('SHA256').update(_tokenString).sign(privKey, 'base64');
  var _tokenBase64WithSignature = base64urlEncode(_tokenString) + '.' + _signature;

  return _tokenBase64WithSignature;
}

function parseToken (jwt, callback) {
  var _segments = jwt.split('.');
  if (_segments.length !== 2) {
    return callback(new Error('Not enough or too many segments'));
  }
  var _tokenBase64 = _segments[0];
  var _signature   = _segments[1];

  try {
    var _tokenString = base64urlDecode(_tokenBase64);
    var _payload = JSON.parse(_tokenString);

    if (!(_payload instanceof Object)) {
      return callback(new Error('Token is not an object'));
    }

    if (_payload.exp && Date.now() > parseInt(_payload.exp, 10) * 1000) {
      return callback(new Error('Token expired'));
    }

    if (_payload.iss === '' || _payload.iss === undefined || _payload.iss === null) {
      return callback(new Error('Token without issuer'));
    }
  }
  catch (e) {
    return callback(new Error('Invalid token ' + e.toString()));
  }
  return callback(null, _payload, _tokenString, _signature);
}

function verifyToken (payload, tokenString, signature, publicKey, callback) {
  try {
    var _verifier = crypto.createVerify('RSA-SHA256').update(tokenString);
    var _isValidSignature = _verifier.verify(publicKey, signature, 'base64');

    if (_isValidSignature === false) {
      return callback(new Error('Invalid token signature'));
    }

  } catch (e) {
    return callback(new Error('Invalid token' + e.toString()));
  }
  return callback(null, payload);
}

function verify (jwt, publicKey, callback) {
  parseToken(jwt, (err, payload, tokenString, signature) => {
    if (err) {
      return callback(err);
    }
    return verifyToken(payload, tokenString, signature, publicKey, callback);
  });
}


function generateAuto (clientId, serverId, privKey, data) {
  // var _cacheKey = clientId + '_' + serverId;
  var _token = generate(clientId, serverId, DEFAULT_EXPIRE_IN, privKey, data);
}

function verifyHTTPHeaderFn (serverId, getPublicKeyFn) {
  return function (req, res, next) {
    if (!req.headers) {
      return next(new Error('No header detected'));
    }
    var _auth = req.headers['Authorization'] || req.headers['authorization'];
    if (typeof _auth !== 'string') {
      return next(new Error('No Authorization HTTP header detected. Format is "Authorization: Bearer token"'));
    }
    if (/^Bearer /i.test(_auth) === false) {
      return next(new Error('No Bearer Token detected. Format is "Authorization: Bearer token"'));
    }
    var _token = _auth.slice(7);

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

module.exports = {
  verify             : verify,
  verifyHTTPHeaderFn : verifyHTTPHeaderFn,
  generate           : generate,
  generateAuto       : generateAuto,
  generateKeys       : generateECDHKeys
};

