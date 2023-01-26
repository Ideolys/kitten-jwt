const should    = require('should');
const jwtVendor = require('jsonwebtoken');
const jwt       = require('../index.js');
const tk        = require('timekeeper');

describe('jsonWebToken', function () {
  before(function() {
    jwt.set({clientCacheSize : 255, serverCacheSize : 255, serverGetPublicKeyErrorCacheExpiration : 60*1000});
  })
  afterEach(function () {
    jwt.set({serverGetPublicKeyErrorCacheExpiration : 60*1000});
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
      let _nbIteration = 500;
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
      should(_tokenPerSecond).be.above(350);
      console.log('\n\n' + _tokenPerSecond + ' token generated per seconds\n');
      done();
    });
  });
  describe('parseCookie()', function () {
    it('should not crash if cookie is undefined or null', function () {
      should(jwt.parseCookie()).equal(null);
      should(jwt.parseCookie(null)).equal(null);
    });
    it('should parse jwt in cookie', function () {
      should(jwt.parseCookie('access_token=azertyu')).equal('azertyu');
      should(jwt.parseCookie('access_token=gfhjfdjfdkfk;Max-age=2019-01-01')).equal('gfhjfdjfdkfk');
      should(jwt.parseCookie('access_token=gfhjfdjfdkfk  ; Max-age=2019-01-01')).equal('gfhjfdjfdkfk');
      should(jwt.parseCookie('access_token=   gfhjfdjfdkfk  ; Max-age=2019-01-01')).equal('gfhjfdjfdkfk');
      should(jwt.parseCookie('  access_token   =   gfhjfdjfdkfk  ; Max-age=2019-01-01')).equal('gfhjfdjfdkfk');
      should(jwt.parseCookie('otherkey=12233;  access_token   =   gfhjfdjfdkfk  ; Max-age=2019-01-01')).equal('gfhjfdjfdkfk');
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
      should(_tokenPerSecond).be.above(450000);
      console.log('\n\n' + _tokenPerSecond + ' tokens per seconds with getToken\n');
      done();
    });
    it('should return data in token', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _data     = {
        id   : 1,
        name : 'test'
      };
      let _token    = jwt.getToken(_clientId, _serverId, getECDHPriv(), _data);
      jwt.verify(_token, getECDHPublic(), (err, payload) => {
        should(err).be.null();
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        should.deepEqual(payload.data, _data);
        done();
      });
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
            should(payload.iss).equal(_clientId);
            done();
          });
        }, 1200);
      });
    });
    it('should accept a parameter to set the current date', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _customNow = Date.now() - 86500 * 1000;
      let _expireIn = -86400;
      let _token = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());
      jwt.verify(_token, getECDHPublic(), (err, payload) => {
        should(err).be.null();
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        should(payload.exp).be.approximately((Date.now()/1000)+_expireIn, 10);
        jwt.verify(_token, getECDHPublic(), (err, payload) => {
          should(err+'').equal('Error: JSON Web Token expired');
          done();
        }, _customNow + 200 * 1000);
      }, _customNow);
    });
    it('should return an error if the token cannot be parsed', function (done) {
      let _token = 'ccc';
      jwt.verify(_token, getECDHPublic(), (err) => {
        should(err+'').equal('Error: Invalid JSON Web Token: Not enough or too many segments');
        done();
      });
    });
    it('should return an error if the token cannot be parsed', function (done) {
      let _token = '..{"toto" : "titi"}';
      jwt.verify(_token, getECDHPublic(), (err) => {
        should(err+'').equal('Error: Invalid JSON Web Token: Unexpected end of JSON input');
        done();
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
          callback(null, getECDHPublic());
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

    it('should accepts tokens without Bearer keyword', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 10;
      let _token    = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, getECDHPublic());
        }, 0);
      }
      let _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      let _req          = {
        headers : {
          Authorization : _token
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

    it('should accepts an array of public keys and tests each one', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 10;
      let _token = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, [
            getECDHPublic2(),
            getECDHPublic2(),
            getECDHPublic()
          ]);
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

    it('should return an error if all public keys are invalid', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 10;
      let _token = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, [
            getECDHPublic2(),
            getECDHPublic2(),
            getECDHPublic2()
          ]);
        }, 0);
      }
      let _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      let _req          = {
        headers : {
          Authorization : 'Bearer ' + _token
        }
      };
      function next (err) {
        should(err+'').be.equal('Error: Invalid JSON Web Token signature');
        done();
      }
      _middlewareFn(_req, {}, next);
    });

    it('should return an error if public keys array is empty (or error) and it should not store the token in the quarantine area if serverGetPublicKeyErrorCacheExpiration is deactivated', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 100;
      let _token = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());

      jwt.set({serverGetPublicKeyErrorCacheExpiration : -1});

      let _currentTestRun = 0;
      let _publicKeyArguments = [
        [null, []],
        [new Error('Bad file'), null],
        [null, null],
        [null, ''],
        [null, undefined],
        [null, getECDHPublic()], // Test immediately
        [null, getECDHPublic()] // Test after 5 second (cache expiration)
      ]
      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(_publicKeyArguments[_currentTestRun][0], _publicKeyArguments[_currentTestRun][1]);
          _currentTestRun++;
        }, 0);
      }
      let _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      let _req          = {
        headers : {
          authorization : 'Bearer ' + _token
        }
      };
      function next (err) {
        should(err+'').be.equal('Error: Empty public key or no public key available');
      }
      function nextOk (err) {
        should(err).be.undefined();
        should(_req.jwtPayload.iss).equal(_clientId);
        should(_req.jwtPayload.aud).equal(_serverId);
        should(_req.jwtPayload.exp).be.approximately((Date.now()/1000)+_expireIn, 10);
        done();
      }
      _middlewareFn(_req, {}, (err) => {
        next(err);
        _middlewareFn(_req, {}, (err) => {
          next(err);
          _middlewareFn(_req, {}, (err) => {
            next(err);
            _middlewareFn(_req, {}, (err) => {
              next(err);
              _middlewareFn(_req, {}, (err) => {
                next(err);
                // this one is ok
                _middlewareFn(_req, {}, (err) => {
                  // getPublicKey is called 6 times
                  should(_currentTestRun).equal(5);
                  nextOk(err);
                });
              });
            });
          });
        });
      });
    });

    it('should return an error if public keys array is empty (or error) AND it should store the token in the quarantine area only during serverGetPublicKeyErrorCacheExpiration time', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 100;
      let _token = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());

      jwt.set({serverGetPublicKeyErrorCacheExpiration : 3 * 1000});

      let _currentTestRun = 0;
      let _publicKeyArguments = [
        [new Error('Bad file'), null], //
        [null, getECDHPublic()]
      ]
      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(_publicKeyArguments[_currentTestRun][0], _publicKeyArguments[_currentTestRun][1]);
          _currentTestRun++;
        }, 0);
      }
      let _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      let _req          = {
        headers : {
          authorization : 'Bearer ' + _token
        }
      };
      function next (err) {
        should(err+'').be.equal('Error: Empty public key or no public key available');
      }
      function nextOk (err) {
        should(err).be.undefined();
        should(_req.jwtPayload.iss).equal(_clientId);
        should(_req.jwtPayload.aud).equal(_serverId);
        should(_req.jwtPayload.exp).be.approximately((Date.now()/1000)+_expireIn, 10);
        done();
      }
      _middlewareFn(_req, {}, (err) => {
        next(err);
        _middlewareFn(_req, {}, (err) => {
          next(err);
          _middlewareFn(_req, {}, (err) => {
            next(err);
            _middlewareFn(_req, {}, (err) => {
              next(err);
              _middlewareFn(_req, {}, (err) => {
                next(err);
                // this one is ok but the token is still in cache for 3 seconds so it still return the error
                _middlewareFn(_req, {}, (err) => {
                  next(err);
                  setTimeout(() => {
                    // getPublicKey is called 2 times
                    should(_currentTestRun).equal(1);
                    // this one is after 3 seconds
                    _middlewareFn(_req, {}, (err) => {
                      nextOk(err);
                    });
                  }, 4000);
                });
              });
            });
          });
        });
      });
    });

    it('should be extremely fast, even if there is a bad token client', function (done) {
      let _nbIteration = 20000;
      let _iteration = 0;
      let _nbNextCalled = 0;
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
          callback(null, getECDHPublic());
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
              let _selectedToken = parseInt(Math.random()*3, 10);
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
              should(_tokenPerSecond).be.above(100000);
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
          callback(null, getECDHPublic());
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
    it('should accepts token in cookies', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      let _expireIn = 10;
      let _token    = jwt.generate(_clientId, _serverId, _expireIn, getECDHPriv());

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, getECDHPublic());
        }, 0);
      }
      let _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      let _req          = {
        headers : {
          cookie : 'access_token='+ _token
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
    it('should return an error if http Authorization header is empty', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, getECDHPublic());
        }, 0);
      }
      let _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      let _req = {
        headers : {}
      };
      function next (err) {
        should(err+'').be.equal('Error: No JSON Web Token detected in Authorization header or Cookie. Format is "Authorization: jwt" or "Cookie: access_token=jwt"');
        done();
      }
      _middlewareFn(_req, {}, next);
    });
    it('should return an error if http Authorization header is undefined', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';
      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, getECDHPublic());
        }, 0);
      }
      let _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      let _req = {};
      function next (err) {
        should(err+'').be.equal('Error: JSON Web Token - No HTTP header detected');
        done();
      }
      _middlewareFn(_req, {}, next);
    });
    it('should return an error if http Authorization header is null (it should not crash)', function (done) {
      let _clientId = '123';
      let _serverId = 'service1';

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, getECDHPublic());
        }, 0);
      }
      let _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      let _req = {
        headers : null
      };
      function next (err) {
        should(err+'').be.equal('Error: JSON Web Token - No HTTP header detected');
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
          callback(null, getECDHPublic());
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
        should(_elapsed).be.below(500);
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
          callback(null, getECDHPublic());
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
          callback(null, getECDHPublic());
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
function getECDHPublic2 () {
  return `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgbcJCeXqEzZgPc+qTnL19QC1c+M4
XtC23FqYCNJBUqX8bvrUIV50W+Enpncrtvfaubo3a1Z7r1EiezgkWJ6Ax2kAyYr9
JibYyLjJF40VphX0I8D7BZmLR3ZNJFb9cQdmS/c3Tc1IRTARYW27Kbb9SooytfXi
RZHOmq9PHStB8TBIbWw=
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
function getECDHPriv2 () {
  return `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBhrbcR3BW3tbTZ5YK3BOXaQrJWLIeVpG5uaJWzRtHxI/qiYnNj4CQ
PySqcryqGpvDL9lV089xskx9/ysn4NW1t0qgBwYFK4EEACOhgYkDgYYABAGBtwkJ
5eoTNmA9z6pOcvX1ALVz4zhe0LbcWpgI0kFSpfxu+tQhXnRb4Semdyu299q5ujdr
VnuvUSJ7OCRYnoDHaQDJiv0mJtjIuMkXjRWmFfQjwPsFmYtHdk0kVv1xB2ZL9zdN
zUhFMBFhbbsptv1KijK19eJFkc6ar08dK0HxMEhtbA==
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

