const should    = require('should');
const crypto    = require('crypto');
const jwtVendor = require('jsonwebtoken');
const jwt       = require('../index.js');
const tk        = require('timekeeper');

describe('jsonWebToken', function () {
  afterEach(function () {
    tk.reset();
    jwt.resetCache();
  });
  describe('generate()', function () {
    it('should generate a token', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 30;
      let _token = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv()); 
      let _payload = getPayload(_token);
      should(_payload.iss).equal(_clientId);
      should(_payload.aud).equal(_serverId);
      should(_payload.exp).be.approximately((Date.now()/1000)+_expireIn, 10);
      done();
    });
    it('should generate a token compatible with jsonwebtoken module', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 30;
      let _token = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv()); 
      let _payload = getPayload(_token);
      jwtVendor.verify(_token, getECDHPublic(), { audience : _serverId, issuer : _clientId }, function (err, decoded) {
        should(err).be.null();
        should(decoded.iss).equal(_clientId);
        should(decoded.aud).equal(_serverId);
        should(decoded.exp).be.approximately((Date.now()/1000)+_expireIn, 10);
        done();
      });
    });
    it('should be fast enough', function (done) {
      let _nbIteration = 1000;
      let _iteration = 0;
      let _tokens = [];
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 30;
      let _start = process.hrtime();
      while (_iteration < _nbIteration) {
        _iteration++;
        _tokens.push(jwt.generate(_clientId, _serverId, _expireIn+_iteration, getECDHPriv())); 
      }
      let _elapsed = getDurationInUS(_start);
      let _tokenPerSecond = parseInt( _iteration / (_elapsed / 1e6) , 10);
      should(_tokenPerSecond).be.above(600);
      console.log('\n\n' + _tokenPerSecond + ' token generated per seconds\n');
      done();
    });
  });
  describe('getToken()', function () {
    it('should generate a token and renew it automatically after 12-hour', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 60 * 60 * 12;
      let _token = jwt.getToken(_clientId, _serverId, getECDHPriv());
      let _payload = getPayload(_token);
      should(_payload.iss).equal(_clientId);
      should(_payload.aud).equal(_serverId);
      should(_payload.exp).be.approximately((Date.now()/1000)+_expireIn, 10);
      // travel in time start + 5 hours
      tk.travel(new Date(Date.now() + 60 * 60 * 5 * 1000));
      let _newToken = jwt.getToken(_clientId, _serverId, getECDHPriv());
      should(_token).equal(_newToken);
      // travel in time start + 7 hours
      tk.travel(new Date(Date.now() + 60 * 60 * 2 * 1000));
      _newToken = jwt.getToken(_clientId, _serverId, getECDHPriv());
      should(_token).equal(_newToken);
      // travel in time start + 13 hours
      tk.travel(new Date(Date.now() + 60 * 60 * 6 * 1000));
      let _newToken2 = jwt.getToken(_clientId, _serverId, getECDHPriv());
      _payload = getPayload(_newToken2);
      should(_payload.exp).be.approximately((Date.now()/1000)+_expireIn , 100);
      should(_token).not.equal(_newToken2);
      // travel in time now + 2 hours
      tk.travel(new Date(Date.now() + 60 * 60 * 2 * 1000));
      let _newToken3 = jwt.getToken(_clientId, _serverId, getECDHPriv());
      should(_newToken2).equal(_newToken3);
      done();
    });
    it('should be extremly fast', function (done) {
      let _nbIteration = 2000;
      let _iteration = 0;
      let _tokens = [];
      let _clientId = '123';
      let _serverId = 'service1';
      let _start = process.hrtime();
      while (_iteration < _nbIteration) {
        _iteration++;
        _tokens.push(jwt.getToken(_clientId, _serverId, getECDHPriv())); 
      }
      let _elapsed = getDurationInUS(_start);
      let _tokenPerSecond = parseInt( _iteration / (_elapsed / 1e6) , 10);
      should(_tokenPerSecond).be.above(500000);
      console.log('\n\n' + _tokenPerSecond + ' tokens per seconds with getToken\n');
      done();
    });
  });
  describe('verify()', function () {
    it('should verify a valid token', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 30;
      let _token = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());
      jwt.verify(_token, getECDHPublic(), (err, payload) => {
        should(err).be.null();
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        should(payload.exp).be.approximately((Date.now()/1000)+_expireIn, 10);
        done();
      });
    });
    it('should return an error if the client id is not valid', function (done) {
      let _clientId = '123';
      let _clientIdOther = '124';
      let _serverId = 'service1';
      let _expireIn = 30;
      let _token = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());
      let _tokenOther = jwt.generate(_clientIdOther, _serverId, _expireIn, getECDHPriv());
      let _tokenSegments = _token.split('.');
      let _otherSegments = _tokenOther.split('.');
      let _tokenBad = _tokenSegments[0] + '.' + _otherSegments[1] + '.' + _tokenSegments[2];
      // check the token is bad
      should(getPayload(_tokenBad).iss).equal(_clientIdOther);
      jwt.verify(_tokenBad, getECDHPublic(), (err, payload) => {
        should(err+'').equal('Error: Invalid JSON Web Token signature');
        done();
      });
    });
    it('should return an error if the server id is not valid', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _serverIdOther = 'service2';
      let _expireIn = 30;
      let _token = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());
      let _tokenOther = jwt.generate(_clientId, _serverIdOther, _expireIn, getECDHPriv());
      let _tokenSegments = _token.split('.');
      let _otherSegments = _tokenOther.split('.');
      let _tokenBad = _tokenSegments[0] + '.' + _otherSegments[1] + '.' + _tokenSegments[2];
      // check the token is bad
      should(getPayload(_tokenBad).aud).equal(_serverIdOther);
      jwt.verify(_tokenBad, getECDHPublic(), (err, payload) => {
        should(err+'').equal('Error: Invalid JSON Web Token signature');
        done();
      });
    });
    it('should return an error if the token is expired', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 1;
      let _token = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());
      jwt.verify(_token, getECDHPublic(), (err, payload) => {
        should(err).be.null();
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        should(payload.exp).be.approximately((Date.now()/1000)+_expireIn, 10);
        setTimeout(() => {
          jwt.verify(_token, getECDHPublic(), (err, payload) => {
            should(err+'').equal('Error: JSON Web Token expired');
            done();
          });
        }, 1200);
      });
    });
    it('should return an error if the signature is not valid', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _serverIdOther = 'service2';
      let _expireIn = 30;
      let _token = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());
      let _tokenOther = jwt.generate(_clientId, _serverIdOther, _expireIn, getECDHPriv());
      let _tokenSegments = _token.split('.');
      let _otherSegments = _tokenOther.split('.');
      let _tokenBad = _tokenSegments[0] + '.' + _tokenSegments[1] + '.' + _otherSegments[2];
      jwt.verify(_token, getECDHPublic(), (err, payload) => {
        should(err).be.null();
        jwt.verify(_tokenBad, getECDHPublic(), (err, payload) => {
          should(err+'').equal('Error: Invalid JSON Web Token signature');
          done();
        });
      });
    });
    it('should return an error if the private key does not match with the public key', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _serverIdOther = 'service2';
      let _expireIn = 30;
      let _token = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());
      jwt.verify(_token, getECDHPublic(), (err, payload) => {
        should(err).be.null();
        jwt.verify(_token, getECDHPublic256(), (err, payload) => {
          should(err+'').equal('Error: Invalid JSON Web Token signature');
          done();
        });
      });
    });
    it('should accepts token generated by node-json-web-token module', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _serverIdOther = 'service2';
      let _expireIn = 30;
      let _expireAt = parseInt(Date.now()/1000) + _expireIn;
      let _token = jwtVendor.sign({ aud : _serverId, iss : _clientId, exp : _expireAt }, getECDHPriv(), { algorithm : 'ES512'});
      jwt.verify(_token, getECDHPublic(), (err, payload) => {
        should(err).be.null();
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        should(payload.exp).be.approximately((Date.now()/1000)+_expireIn, 10);
        done();
      });
    });
  });
  describe('verifyHTTPHeaderFn()', function () {
    it('should generate a function which verify Token', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 10;
      let _token    = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(getECDHPublic());
        }, 0);
      }
      let _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      let _req          = {
        headers : {
          Authorization : 'Bearer ' + _token
        }
      };
      function next (err) {
        should(err).be.undefined();
        should(_req.jwtPayload.iss).equal(_clientId);
        should(_req.jwtPayload.aud).equal(_serverId);
        should(_req.jwtPayload.exp).be.approximately((Date.now()/1000)+_expireIn, 10);
        done();
      }
      _middlewareFn(_req, {}, next);
    });
    it('should be extremely fast, even if there is a bad token client', function (done) {
      let _nbIteration = 2000;
      let _iteration = 0;
      let _nbNextCalled = 0;
      let _clientId = '1';
      let _serverId = 'service1';
      let _expireIn = 10;
      let _token1    = jwt.generate('0', _serverId, _expireIn, getECDHPriv());
      let _token2    = jwt.generate('1', _serverId, _expireIn, getECDHPriv());
      let _badToken3 = jwt.generate('2', _serverId, -10, getECDHPriv());
      let _tokens          = ['Bearer ' + _token1, 'Bearer ' + _token2, 'Bearer ' + _badToken3];
      let _nbTokenToVerify = [0, 0, 0];
      let _nbTokenVerifiedOk = 0;
      let _nbTokenVerifiedKo = 0;
      function getPublicKeyFn (req, res, payload, callback) {
        return setTimeout(() => {
          callback(getECDHPublic());
        }, 100);
      }
      let _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      let _req = { headers : { authorization : '' } };
      // pre-warm cache
      _req.headers.authorization = _tokens[0];
      _middlewareFn(_req, {}, function () {
        _req.headers.authorization = _tokens[1];
        _middlewareFn(_req, {}, function () {
          _req.headers.authorization = _tokens[2];
          _middlewareFn(_req, {}, function () {
            let _start = process.hrtime();
            while (_iteration < _nbIteration) {
              _iteration++;
              let _selectedToken = parseInt(Math.random()*3);
              _nbTokenToVerify[_selectedToken]++;
              let _req = { headers : { authorization : _tokens[_selectedToken] } };
              _middlewareFn(_req, {}, nextIteration);
            }
            function nextIteration (err) {
              _nbNextCalled++;
              if (err) {
                _nbTokenVerifiedKo++;
              }
              else {
                _nbTokenVerifiedOk++;
              }
              if (_nbNextCalled === _nbIteration) {
                theEnd();
              }
            }
            function theEnd () {
              let _elapsed = getDurationInUS(_start);
              let _tokenPerSecond = parseInt( _iteration / (_elapsed / 1e6) , 10);
              should(_nbTokenToVerify[0] + _nbTokenToVerify[1]).eql(_nbTokenVerifiedOk);
              should(_nbTokenToVerify[2]).eql(_nbTokenVerifiedKo);
              should(_tokenPerSecond).be.above(400000);
              console.log('\n\n' + _tokenPerSecond + ' tokens per seconds verified by verifyHTTPHeaderFn middleware\n');
              done();
            }
          });
        });
      });
    });
    // The RFC for HTTP (as cited above) dictates that the headers are case-insensitive
    it('should accepts headers with lower case. req.jwtPayload should still be defined if cache is used', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 10;
      let _token    = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(getECDHPublic());
        }, 0);
      }
      let _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      let _req          = {
        headers : {
          authorization : 'bearer ' + _token
        }
      };
      function next (err) {
        should(err).be.undefined();
        should(_req.jwtPayload.iss).equal(_clientId);
        should(_req.jwtPayload.aud).equal(_serverId);
        should(_req.jwtPayload.exp).be.approximately((Date.now()/1000)+_expireIn, 10);
        delete _req.jwtPayload;
        _middlewareFn(_req, {}, () => {
          // _req.jwtPayload should be defined even if cache is used (second call)
          should(_req.jwtPayload.iss).equal(_clientId);
          should(_req.jwtPayload.aud).equal(_serverId);
          done();
        });
      }
      _middlewareFn(_req, {}, next);
    });
    it('should return an error if http Authorization header is undefined', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 10;
      let _token    = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(getECDHPublic());
        }, 0);
      }
      let _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      let _req = {
        headers : {}
      };
      function next (err) {
        should(err+'').be.equal('Error: No Authorization HTTP header detected. Format is "Authorization: Bearer jwt"');
        done();
      }
      _middlewareFn(_req, {}, next);
    });
    it('should return an error if the token is expired. And it should be faster the second time (cache)', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 1;
      let _token    = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());
      let _start    = 0;

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(getECDHPublic());
        }, 0);
      }
      let _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      let _req = {
        headers : {
          Authorization : 'Bearer ' + _token
        }
      };
      function next (err) {
        should(err+'').be.equal('Error: JSON Web Token expired');
        _start = process.hrtime();
        // should return the same error both (cache is used if asked two times)
        _middlewareFn(_req, {}, (err) => {
          _middlewareFn(_req, {}, (err) => {
            _middlewareFn(_req, {}, (err) => {
              nextAndEnd(err);
            });
          });
        });
      }
      function nextAndEnd (err) {
        should(err+'').be.equal('Error: JSON Web Token expired');
        let _elapsed = getDurationInUS(_start);
        should(_elapsed).be.below(220);
        done();
      }
      setTimeout(() => {
        _middlewareFn(_req, {}, next);
      }, 1200);
    });
    it('should return an error if the token is expired, even is it cached (NOT THE SAME TEST AS ABOVE)', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 1;
      let _token    = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(getECDHPublic());
        }, 0);
      }
      let _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      let _req = {
        headers : {
          Authorization : 'Bearer ' + _token
        }
      };
      function next (err) {
        should(err+'').be.equal('Error: JSON Web Token expired');
        done();
      }
      // let the module put the token in the cache when it is still valid
      _middlewareFn(_req, {}, (err) => {
        should(err).be.undefined();
        setTimeout(() => {
          // and check again to verify the cache does not break expiration check
          _middlewareFn(_req, {}, next);
        }, 1200);
      });
    });
    it('should return an error if the audience is not valid', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 10;
      let _token    = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(getECDHPublic());
        }, 0);
      }
      let _middlewareFn = jwt.verifyHTTPHeaderFn('otherServer', getPublicKeyFn);
      let _req = {
        headers : {
          Authorization : 'Bearer ' + _token
        }
      };
      function next (err) {
        should(err+'').be.equal('Error: Invalid JSON Web Token audience');
        done();
      }
      _middlewareFn(_req, {}, next);
    });
  });
});


// prime256v1
function getECDHPublic256 () {
  return '-----BEGIN PUBLIC KEY-----\n'
        +'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVzKI2nSLwOfDjaWsdfkGUuGFEeSh\n'
        +'Y9RtMeCj7PBF2p3vFE1QrEBCNkKqTyK0fhpHiVhiuOWwzNpKQGx1/X2rSg==\n'
        +'-----END PUBLIC KEY-----\n'
  ;
}
function getECDHPriv256 () { 
  return '-----BEGIN EC PRIVATE KEY-----\n'
       + 'MHcCAQEEIDCxGMFiS4IcWTYoc2esZqMpk7GgDc+sWpzX1bTrEpQ9oAoGCCqGSM49\n'
       + 'AwEHoUQDQgAEVzKI2nSLwOfDjaWsdfkGUuGFEeShY9RtMeCj7PBF2p3vFE1QrEBC\n'
       + 'NkKqTyK0fhpHiVhiuOWwzNpKQGx1/X2rSg==\n'
       + '-----END EC PRIVATE KEY-----\n';
}

// secp521r1
function getECDHPublic () {
  return `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAFyuBMMabuKuiRcSkgCPdThV4fZK3
CEFcK07JndIa+Gals5/JC5kQAlcnPtu3dpMbqwFcw8k7Axdd/yldr+mnOo8Bb+Xx
ENwtgO5nQO4w1IVvXBFHQP5s/HtI+VPquJBeI75PqbAWQaUXTdkyF4nEpTUsnT7h
mV+8hper5VKVe1cTfsg=
-----END PUBLIC KEY-----
`;
}
function getECDHPriv () { 
  return `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBPVWtkiEJWdPW1t8+CYAMKBr1VdAO4sU15AZNJopFcRdeCZSEOOF2
eUhAFocH57oBaoi9NQP5BFbsYjVjo7biZbmgBwYFK4EEACOhgYkDgYYABAAXK4Ew
xpu4q6JFxKSAI91OFXh9krcIQVwrTsmd0hr4ZqWzn8kLmRACVyc+27d2kxurAVzD
yTsDF13/KV2v6ac6jwFv5fEQ3C2A7mdA7jDUhW9cEUdA/mz8e0j5U+q4kF4jvk+p
sBZBpRdN2TIXicSlNSydPuGZX7yGl6vlUpV7VxN+yA==
-----END EC PRIVATE KEY-----
`;     
}

function getPayload (token, encoded) {
  var _segments = token.split('.');
  var _payloadSeg = _segments[1];
  var _payload = JSON.parse(base64urlDecode(_payloadSeg));
  if (encoded) {
    _payload = _payloadSeg;
  }
  return _payload;
}

function getHeader (token, encoded) {
  var _segments = token.split('.');
  var _headerSeg = _segments[0];
  var _header = JSON.parse(base64urlDecode(_headerSeg));
  if (encoded) {
    _header = _headerSeg;
  }
  return _header;
}

function getSignature (token) {
  var _segments = token.split('.');
  var _signatureSeg = _segments[1];
  return _signatureSeg;
}

function base64urlDecode (str) {
  return new Buffer(base64urlUnescape(str), 'base64').toString();
}

function base64urlUnescape (str) {
  str += new Array(5 - str.length % 4).join('=');
  return str.replace(/\-/g, '+').replace(/_/g, '/');
}

function getDurationInUS (time) {
  var _interval = process.hrtime(time);
  return _interval[0] * 1e6 + parseInt(_interval[1] / 1e3, 10);
}

