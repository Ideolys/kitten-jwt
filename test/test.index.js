var should  = require('should');
var crypto  = require('crypto');
var jwt     = require('../index.js');

describe('jsonWebToken', function () {
  describe('generate()', function () {
    it('should generate a token', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 30;
      let _token = jwt.generate(_clientId, _serverId, _expireIn, getPrivKey()); 
      let _payload = getPayload(_token);
      should(_payload.iss).equal(_clientId);
      should(_payload.aud).equal(_serverId);
      should(_payload.exp).be.approximately((Date.now()/1000)+_expireIn, 10);
      done();
    });
  });
  describe('verify()', function () {
    it('should verify a valid token', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 30;
      let _token = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv2());
      jwt.verify(_token, getECDHPublic2(), (err, payload) => {
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
      let _token = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv2());
      let _tokenOther = jwt.generate(_clientIdOther, _serverId, _expireIn, getECDHPriv2());
      let _payloadOther = _tokenOther.split('.')[0];
      let _tokenBad = _payloadOther + '.' + _token.split('.')[1];
      // check the token is bad
      should(getPayload(_tokenBad).iss).equal(_clientIdOther);
      jwt.verify(_tokenBad, getECDHPublic2(), (err, payload) => {
        should(err+'').equal('Error: Invalid token signature');
        done();
      });
    });
    it('should return an error if the server id is not valid', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _serverIdOther = 'service2';
      let _expireIn = 30;
      let _token = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv2());
      let _tokenOther = jwt.generate(_clientId, _serverIdOther, _expireIn, getECDHPriv2());
      let _payloadOther = _tokenOther.split('.')[0];
      let _tokenBad = _payloadOther + '.' + _token.split('.')[1];
      // check the token is bad
      should(getPayload(_tokenBad).aud).equal(_serverIdOther);
      jwt.verify(_tokenBad, getECDHPublic2(), (err, payload) => {
        should(err+'').equal('Error: Invalid token signature');
        done();
      });
    });
    it('should return an error if the token is expired', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 1;
      let _token = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv2());
      jwt.verify(_token, getECDHPublic2(), (err, payload) => {
        should(err).be.null();
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        should(payload.exp).be.approximately((Date.now()/1000)+_expireIn, 10);
        setTimeout(() => {
          jwt.verify(_token, getECDHPublic2(), (err, payload) => {
            should(err+'').equal('Error: Token expired');
            done();
          });
        }, 1200);
      });
    });
  });
  describe('verifyHTTPHeaderFn()', function () {
    it('should generate a function which verify Token', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 10;
      let _token        = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv2());

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(getECDHPublic2());
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
    it('should return an error if http Authorization header is undefined', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 10;
      let _token    = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv2());

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(getECDHPublic2());
        }, 0);
      }
      let _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      let _req = {
        headers : {}
      };
      function next (err) {
        should(err+'').be.equal('Error: No Authorization HTTP header detected. Format is "Authorization: Bearer token"');
        done();
      }
      _middlewareFn(_req, {}, next);
    });
    it('should return an error if the token is expired', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 1;
      let _token    = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv2());

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(getECDHPublic2());
        }, 0);
      }
      let _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      let _req = {
        headers : {
          Authorization : 'Bearer ' + _token
        }
      };
      function next (err) {
        should(err+'').be.equal('Error: Token expired');
        done();
      }
      setTimeout(() => {
        _middlewareFn(_req, {}, next);
      }, 1200);
    });
    it('should return an error if the audience is not valid', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 10;
      let _token    = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv2());

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(getECDHPublic2());
        }, 0);
      }
      let _middlewareFn = jwt.verifyHTTPHeaderFn('otherServer', getPublicKeyFn);
      let _req = {
        headers : {
          Authorization : 'Bearer ' + _token
        }
      };
      function next (err) {
        should(err+'').be.equal('Error: Invalid token audience');
        done();
      }
      _middlewareFn(_req, {}, next);
    });
  });
});



function getECDHPublic () {
  // prime256v1
  return '-----BEGIN PUBLIC KEY-----\n'
        +'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVzKI2nSLwOfDjaWsdfkGUuGFEeSh\n'
        +'Y9RtMeCj7PBF2p3vFE1QrEBCNkKqTyK0fhpHiVhiuOWwzNpKQGx1/X2rSg==\n'
        +'-----END PUBLIC KEY-----\n'
  ;
}

function getECDHPriv () { 
  return '-----BEGIN EC PRIVATE KEY-----\n'
       + 'MHcCAQEEIDCxGMFiS4IcWTYoc2esZqMpk7GgDc+sWpzX1bTrEpQ9oAoGCCqGSM49\n'
       + 'AwEHoUQDQgAEVzKI2nSLwOfDjaWsdfkGUuGFEeShY9RtMeCj7PBF2p3vFE1QrEBC\n'
       + 'NkKqTyK0fhpHiVhiuOWwzNpKQGx1/X2rSg==\n'
       + '-----END EC PRIVATE KEY-----\n';
}


function getECDHPublic2 () {
  // secp521r1
  return `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAFyuBMMabuKuiRcSkgCPdThV4fZK3
CEFcK07JndIa+Gals5/JC5kQAlcnPtu3dpMbqwFcw8k7Axdd/yldr+mnOo8Bb+Xx
ENwtgO5nQO4w1IVvXBFHQP5s/HtI+VPquJBeI75PqbAWQaUXTdkyF4nEpTUsnT7h
mV+8hper5VKVe1cTfsg=
-----END PUBLIC KEY-----
`;

}

function getECDHPriv2 () { 
  return `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBPVWtkiEJWdPW1t8+CYAMKBr1VdAO4sU15AZNJopFcRdeCZSEOOF2
eUhAFocH57oBaoi9NQP5BFbsYjVjo7biZbmgBwYFK4EEACOhgYkDgYYABAAXK4Ew
xpu4q6JFxKSAI91OFXh9krcIQVwrTsmd0hr4ZqWzn8kLmRACVyc+27d2kxurAVzD
yTsDF13/KV2v6ac6jwFv5fEQ3C2A7mdA7jDUhW9cEUdA/mz8e0j5U+q4kF4jvk+p
sBZBpRdN2TIXicSlNSydPuGZX7yGl6vlUpV7VxN+yA==
-----END EC PRIVATE KEY-----
`;     
}

function getPrivKey () {
  return `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`;
}

function getPubKey () {
  return `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAtUvmYO9rk8tZQVhg0isK
psGkp5kFUFrqf094irfwtP/DQwYVJxCmkGhVfp+u/QjPx3eImB5vXm6s9Zl8TnqL
6Fsjq3a0wNnnRDHIu0oHdWKNknjIkzfwOptLqYKArvOnjjlI0xFPz9AE9/qb6G37
BFOK9G2NkarpEXepnP1nXruGaX9B/jz7HSeeokiX8r8X+h2rzrko7aie/DAQUWuo
9mV5q20GD7aV6CekDJg5Av842IruNOxZoAfzXtCKiduZvkmc31Zz8V3mP6Yl53Ki
yENIo+/U8gG3AHcKK73UpXo1aV1g7KhXTGAsoSfP9EqvtXJjFoQT6tbteBqDRZgs
aZ1HILYwdYywLIJZCVaxpc+AQqYV5QiJ8YHUI8phhY847wh7OJX6lxAIVmgXMG7u
+ZpucNLLwjVyd9y0aRHvOeYWB0W/SROv6SdtU4fMnRqNarC35TLqS1nF8qo2D1zu
ZqnKNolv1XpIVf5korFINrmM4E/8d+MeVZhEbACwb28RAgMBAAE=
-----END PUBLIC KEY-----;
`;
}

function getPayload (token, encoded) {
  var _segments = token.split('.');
  var _payloadSeg = _segments[0];
  var _payload = JSON.parse(base64urlDecode(_payloadSeg));
  if (encoded) {
    _payload = _payloadSeg;
  }
  return _payload;
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
