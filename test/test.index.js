const should = require('should');
const jwtVendor = require('jsonwebtoken');
const jwt = require('../index.js');
const tk = require('timekeeper');

describe('jsonWebToken', function () {
  before(function () {
    jwt.set({ clientCacheSize : 255, serverCacheSize : 255, serverGetPublicKeyErrorCacheExpiration : 60 * 1000 });
  });
  afterEach(function () {
    jwt.set({ serverGetPublicKeyErrorCacheExpiration : 60 * 1000 });
    tk.reset();
    jwt.resetCache();
  });
  describe('generate()', () => {
    it('should generate a token', done => {
      const options = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 30,
        },
        privKey : getECDHPriv()
      };
      const _token = jwt.generate(options);
      const _payload = getPayload(_token);

      should(_payload.iss).equal(options.payload.clientId);
      should(_payload.aud).equal(options.payload.serverId);
      should(_payload.exp).be.approximately((Date.now() / 1000) + options.payload.expiresIn, 10);

      done();
    });
    it('should generate a token with custom alg', done => {
      const priv = getRSAPriv().split(String.raw`\n`).join('\n');
      const options = {
        header : {
          alg : 'RS256',
          kid : '45560071F1834ADA450C9260B562741DAE0B6C8B'
        },
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 30,
        },
        privKey : priv,
      };
      const _token = jwt.generate(options);
      const _payload = getPayload(_token);
      const _header = getHeader(_token);

      should(_header.alg).equal(options.header.alg);
      should(_header.kid).equal(options.header.kid);
      should(_payload.iss).equal(options.payload.clientId);
      should(_payload.aud).equal(options.payload.serverId);
      should(_payload.exp).be.approximately((Date.now() / 1000) + options.payload.expiresIn, 10);

      done();
    });
    it('should generate a token compatible with jsonwebtoken module', done => {
      const options = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 30,
        },
        privKey : getECDHPriv()
      };
      const _token = jwt.generate(options);

      jwtVendor.verify(
        _token,
        getECDHPublic(),
        {
          audience : options.payload.serverId,
          issuer   : options.payload.clientId
        },
        (err, decoded) => {
          should(err).be.null();
          should(decoded.iss).equal(options.payload.clientId);
          should(decoded.aud).equal(options.payload.serverId);
          should(decoded.exp).be.approximately((Date.now() / 1000) + options.payload.expiresIn, 10);

          done();
        });
    });
    it('should generate a token compatible with jsonwebtoken module using custom alg', done => {
      const options = {
        header : {
          alg : 'RS256',
          kid : '45560071F1834ADA450C9260B562741DAE0B6C8B'
        },
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 30,
        },
        privKey : getRSAPriv(),
      };
      const _token = jwt.generate(options);

      jwtVendor.verify(
        _token,
        getRSAPub(),
        {
          audience   : options.payload.serverId,
          issuer     : options.payload.clientId,
          algorithms : options.header.alg
        },
        (err, decoded) => {
          should(err).be.null();
          should(decoded.iss).equal(options.payload.clientId);
          should(decoded.aud).equal(options.payload.serverId);
          should(decoded.exp).be.approximately((Date.now() / 1000) + options.payload.expiresIn, 10);

          done();
        });
    });
    it('should be fast enough', function (done) {
      const _nbIteration = 500;
      let _iteration = 0;
      const _tokens = [];
      const _start = process.hrtime();
      const options = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 30,
        },
        privKey : getECDHPriv()
      };
      while (_iteration < _nbIteration) {
        _iteration++;
        _tokens.push(jwt.generate({ ... options, expiresIn : options.expiresIn + _iteration }));
      }
      const _elapsed = getDurationInUS(_start);
      const _tokenPerSecond = parseInt(_iteration / (_elapsed / 1e6), 10);
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
      const _clientId = '123';
      const _serverId = 'service1';
      const _expireIn = 60 * 60 * 12;
      const _token = jwt.getToken(_clientId, _serverId, getECDHPriv());
      let _payload = getPayload(_token);
      should(_payload.iss).equal(_clientId);
      should(_payload.aud).equal(_serverId);
      should(_payload.exp).be.approximately((Date.now() / 1000) + _expireIn, 10);
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
      const _newToken2 = jwt.getToken(_clientId, _serverId, getECDHPriv());
      _payload = getPayload(_newToken2);
      should(_payload.exp).be.approximately((Date.now() / 1000) + _expireIn, 100);
      should(_token).not.equal(_newToken2);
      // travel in time now + 2 hours
      tk.travel(new Date(Date.now() + 60 * 60 * 2 * 1000));
      const _newToken3 = jwt.getToken(_clientId, _serverId, getECDHPriv());
      should(_newToken2).equal(_newToken3);
      done();
    });
    it('should be extremly fast', function (done) {
      const _nbIteration = 2000;
      let _iteration = 0;
      const _tokens = [];
      const _clientId = '123';
      const _serverId = 'service1';
      const _start = process.hrtime();
      while (_iteration < _nbIteration) {
        _iteration++;
        _tokens.push(jwt.getToken(_clientId, _serverId, getECDHPriv()));
      }
      const _elapsed = getDurationInUS(_start);
      const _tokenPerSecond = parseInt(_iteration / (_elapsed / 1e6), 10);
      should(_tokenPerSecond).be.above(450000);
      console.log('\n\n' + _tokenPerSecond + ' tokens per seconds with getToken\n');
      done();
    });
    it('should return data in token', function (done) {
      const _clientId = '123';
      const _serverId = 'service1';
      const _data = {
        id   : 1,
        name : 'test'
      };
      const _token = jwt.getToken(_clientId, _serverId, getECDHPriv(), _data);
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
      const options = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 30,
        },
        privKey : getECDHPriv()
      };
      const _token = jwt.generate(options);

      jwt.verify(_token, getECDHPublic(), (err, payload) => {
        should(err).be.null();
        should(payload.iss).equal(options.payload.clientId);
        should(payload.aud).equal(options.payload.serverId);
        should(payload.exp).be.approximately((Date.now() / 1000) + options.payload.expiresIn, 10);
        done();
      });
    });
    it('should return an error if the client id is not valid', done => {
      const optionsSomeClient = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 30,
        },
        privKey : getECDHPriv()
      };
      const optionsAnotherClient = {
        ... optionsSomeClient,
        payload : {
          ... optionsSomeClient.payload,
          clientId : '124',
        }
      };
      const _token      = jwt.generate(optionsSomeClient);
      const _tokenOther = jwt.generate(optionsAnotherClient);
      const _tokenSegments = _token.split('.');
      const _otherSegments = _tokenOther.split('.');
      const _tokenBad      = _tokenSegments[0] + '.' + _otherSegments[1] + '.' + _tokenSegments[2];
      // check the token is bad
      should(getPayload(_tokenBad).iss).equal(optionsAnotherClient.payload.clientId);
      jwt.verify(_tokenBad, getECDHPublic(), err => {
        should(err + '').equal('Error: Invalid JSON Web Token signature');
        done();
      });
    });
    it('should return an error if the server id is not valid', done => {
      const optionsSomeClient = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 30,
        },
        privKey : getECDHPriv()
      };
      const optionsAnotherClient = {
        ... optionsSomeClient,
        payload : {
          ... optionsSomeClient.payload,
          serverId : 'service2',
        }
      };
      const _token      = jwt.generate(optionsSomeClient);
      const _tokenOther = jwt.generate(optionsAnotherClient);
      const _tokenSegments = _token.split('.');
      const _otherSegments = _tokenOther.split('.');
      const _tokenBad      = _tokenSegments[0] + '.' + _otherSegments[1] + '.' + _tokenSegments[2];
      // check the token is bad
      should(getPayload(_tokenBad).aud).equal(optionsAnotherClient.payload.serverId);
      jwt.verify(_tokenBad, getECDHPublic(), err => {
        should(err + '').equal('Error: Invalid JSON Web Token signature');
        done();
      });
    });
    it('should return an error if the token is expired', function (done) {
      const options = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 1,
        },
        privKey : getECDHPriv()
      };
      const _token = jwt.generate(options);

      jwt.verify(_token, getECDHPublic(), (err, payload) => {
        should(err).be.null();
        should(payload.iss).equal(options.payload.clientId);
        should(payload.aud).equal(options.payload.serverId);
        should(payload.exp).be.approximately((Date.now() / 1000) + options.payload.expiresIn, 10);
        setTimeout(() => {
          jwt.verify(_token, getECDHPublic(), (err, _payload) => {
            should(err + '').equal('Error: JSON Web Token expired');
            should(_payload.iss).equal(options.payload.clientId);
            done();
          });
        }, 1200);
      });
    });
    it('should accept a parameter to set the current date', function (done) {
      const _customNow = Date.now() - 86500 * 1000;
      const options = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : -86400,
        },
        privKey : getECDHPriv()
      };
      const _token = jwt.generate(options);
      jwt.verify(_token, getECDHPublic(), (err, payload) => {
        should(err).be.null();
        should(payload.iss).equal(options.payload.clientId);
        should(payload.aud).equal(options.payload.serverId);
        should(payload.exp).be.approximately((Date.now() / 1000) + options.payload.expiresIn, 10);
        jwt.verify(_token, getECDHPublic(), err => {
          should(err + '').equal('Error: JSON Web Token expired');
          done();
        }, _customNow + 200 * 1000);
      }, _customNow);
    });
    it('should return an error if the token cannot be parsed', function (done) {
      const _token = 'ccc';
      jwt.verify(_token, getECDHPublic(), (err) => {
        should(err + '').equal('Error: Invalid JSON Web Token: Not enough or too many segments');
        done();
      });
    });
    it('should return an error if the token cannot be parsed', function (done) {
      const _token = '..{"toto" : "titi"}';
      jwt.verify(_token, getECDHPublic(), (err) => {
        should(err + '').equal('Error: Invalid JSON Web Token: Unexpected end of JSON input');
        done();
      });
    });
    it('should return an error if the signature is not valid', done => {
      const optionsSomeClient = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 30,
        },
        privKey : getECDHPriv()
      };
      const optionsAnotherClient = {
        ... optionsSomeClient,
        payload : {
          ... optionsSomeClient.payload,
          serverId : 'service2',
        }
      };
      const _token      = jwt.generate(optionsSomeClient);
      const _tokenOther = jwt.generate(optionsAnotherClient);
      const _tokenSegments = _token.split('.');
      const _otherSegments = _tokenOther.split('.');
      const _tokenBad      = _tokenSegments[0] + '.' + _tokenSegments[1] + '.' + _otherSegments[2];
      jwt.verify(_token, getECDHPublic(), err => {
        should(err).be.null();
        jwt.verify(_tokenBad, getECDHPublic(), err => {
          should(err + '').equal('Error: Invalid JSON Web Token signature');
          done();
        });
      });
    });
    it('should return an error if the private key does not match with the public key', done => {
      const options = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 30,
        },
        privKey : getECDHPriv()
      };
      const _token = jwt.generate(options);
      jwt.verify(_token, getECDHPublic(), err => {
        should(err).be.null();
        jwt.verify(_token, getECDHPublic256(), err => {
          should(err + '').equal('Error: Invalid JSON Web Token signature');
          done();
        });
      });
    });
    it('should accepts token generated by node-json-web-token module', done => {
      const _clientId = '123';
      const _serverId = 'service1';
      const _expireIn = 30;
      const _expireAt = (Date.now() / 1000) + _expireIn;
      const _token = jwtVendor.sign({ aud : _serverId, iss : _clientId, exp : _expireAt }, getECDHPriv(), { algorithm : 'ES512' });
      jwt.verify(_token, getECDHPublic(), (err, payload) => {
        should(err).be.null();
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        should(payload.exp).be.approximately((Date.now() / 1000) + _expireIn, 10);
        done();
      });
    });
  });
  describe('verifyHTTPHeaderFn()', function () {
    it('should generate a function which verify Token', done => {
      const options = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 10,
        },
        privKey : getECDHPriv()
      };
      const _token = jwt.generate(options);

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(options.payload.clientId);
        should(payload.aud).equal(options.payload.serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, getECDHPublic());
        }, 0);
      }
      const _middlewareFn = jwt.verifyHTTPHeaderFn(options.payload.serverId, getPublicKeyFn);
      const _req = {
        headers : {
          Authorization : 'Bearer ' + _token
        }
      };
      function next (err) {
        should(err).be.undefined();
        should(_req.jwtPayload.iss).equal(options.payload.clientId);
        should(_req.jwtPayload.aud).equal(options.payload.serverId);
        should(_req.jwtPayload.exp).be.approximately((Date.now() / 1000) + options.payload.expiresIn, 10);
        done();
      }
      _middlewareFn(_req, {}, next);
    });

    it('should accepts tokens without Bearer keyword', done => {
      const options = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 10,
        },
        privKey : getECDHPriv()
      };
      const _token = jwt.generate(options);

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(options.payload.clientId);
        should(payload.aud).equal(options.payload.serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, getECDHPublic());
        }, 0);
      }
      const _middlewareFn = jwt.verifyHTTPHeaderFn(options.payload.serverId, getPublicKeyFn);
      const _req = {
        headers : {
          Authorization : _token
        }
      };
      function next (err) {
        should(err).be.undefined();
        should(_req.jwtPayload.iss).equal(options.payload.clientId);
        should(_req.jwtPayload.aud).equal(options.payload.serverId);
        should(_req.jwtPayload.exp).be.approximately((Date.now() / 1000) + options.payload.expiresIn, 10);
        done();
      }
      _middlewareFn(_req, {}, next);
    });

    it('should accepts an array of public keys and tests each one', done => {
      const options = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 10,
        },
        privKey : getECDHPriv()
      };
      const _token = jwt.generate(options);

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(options.payload.clientId);
        should(payload.aud).equal(options.payload.serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, [
            getECDHPublic2(),
            getECDHPublic2(),
            getECDHPublic()
          ]);
        }, 0);
      }
      const _middlewareFn = jwt.verifyHTTPHeaderFn(options.payload.serverId, getPublicKeyFn);
      const _req = {
        headers : {
          Authorization : 'Bearer ' + _token
        }
      };
      function next (err) {
        should(err).be.undefined();
        should(_req.jwtPayload.iss).equal(options.payload.clientId);
        should(_req.jwtPayload.aud).equal(options.payload.serverId);
        should(_req.jwtPayload.exp).be.approximately((Date.now() / 1000) + options.payload.expiresIn, 10);
        done();
      }
      _middlewareFn(_req, {}, next);
    });

    it('should return an error if all public keys are invalid', done => {
      const options = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 10,
        },
        privKey : getECDHPriv()
      };
      const _token = jwt.generate(options);

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(options.payload.clientId);
        should(payload.aud).equal(options.payload.serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, [
            getECDHPublic2(),
            getECDHPublic2(),
            getECDHPublic2()
          ]);
        }, 0);
      }
      const _middlewareFn = jwt.verifyHTTPHeaderFn(options.payload.serverId, getPublicKeyFn);
      const _req = {
        headers : {
          Authorization : 'Bearer ' + _token
        }
      };
      function next (err) {
        should(err + '').be.equal('Error: Invalid JSON Web Token signature');
        done();
      }
      _middlewareFn(_req, {}, next);
    });

    it('should return an error if public keys array is empty (or error) and it should not store the token in the quarantine area if serverGetPublicKeyErrorCacheExpiration is deactivated', done => {
      const options = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 100,
        },
        privKey : getECDHPriv()
      };
      const _token = jwt.generate(options);

      jwt.set({ serverGetPublicKeyErrorCacheExpiration : -1 });

      let _currentTestRun = 0;
      const _publicKeyArguments = [
        [null, []],
        [new Error('Bad file'), null],
        [null, null],
        [null, ''],
        [null, undefined],
        [null, getECDHPublic()], // Test immediately
        [null, getECDHPublic()] // Test after 5 second (cache expiration)
      ];
      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(options.payload.clientId);
        should(payload.aud).equal(options.payload.serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(_publicKeyArguments[_currentTestRun][0], _publicKeyArguments[_currentTestRun][1]);
          _currentTestRun++;
        }, 0);
      }
      const _middlewareFn = jwt.verifyHTTPHeaderFn(options.payload.serverId, getPublicKeyFn);
      const _req = {
        headers : {
          authorization : 'Bearer ' + _token
        }
      };
      function next (err) {
        should(err + '').be.equal('Error: Empty public key or no public key available');
      }
      function nextOk (err) {
        should(err).be.undefined();
        should(_req.jwtPayload.iss).equal(options.payload.clientId);
        should(_req.jwtPayload.aud).equal(options.payload.serverId);
        should(_req.jwtPayload.exp).be.approximately((Date.now() / 1000) + options.payload.expiresIn, 10);
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

    it('should return an error if public keys array is empty (or error) AND it should store the token in the quarantine area only during serverGetPublicKeyErrorCacheExpiration time', done => {
      const options = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 100,
        },
        privKey : getECDHPriv()
      };
      const _token = jwt.generate(options);

      jwt.set({ serverGetPublicKeyErrorCacheExpiration : 3 * 1000 });

      let _currentTestRun = 0;
      const _publicKeyArguments = [
        [new Error('Bad file'), null], //
        [null, getECDHPublic()]
      ];
      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(options.payload.clientId);
        should(payload.aud).equal(options.payload.serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(_publicKeyArguments[_currentTestRun][0], _publicKeyArguments[_currentTestRun][1]);
          _currentTestRun++;
        }, 0);
      }
      const _middlewareFn = jwt.verifyHTTPHeaderFn(options.payload.serverId, getPublicKeyFn);
      const _req = {
        headers : {
          authorization : 'Bearer ' + _token
        }
      };
      function next (err) {
        should(err + '').be.equal('Error: Empty public key or no public key available');
      }
      function nextOk (err) {
        should(err).be.undefined();
        should(_req.jwtPayload.iss).equal(options.payload.clientId);
        should(_req.jwtPayload.aud).equal(options.payload.serverId);
        should(_req.jwtPayload.exp).be.approximately((Date.now() / 1000) + options.payload.expiresIn, 10);
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

    it('should be extremely fast, even if there is a bad token client', done => {
      const _nbIteration = 20000;
      let _iteration     = 0;
      let _nbNextCalled  = 0;

      const _options1 = {
        payload : {
          clientId  : '0',
          serverId  : 'service1',
          expiresIn : 10,
        },
        privKey : getECDHPriv()
      };
      const _options2 = {
        ... _options1,
        payload : {
          ... _options1.payload,
          clientId : '1',
        }
      };
      const _options3 = {
        ... _options1,
        payload : {
          ... _options1.payload,
          clientId  : '2',
          expiresIn : -10
        }
      };

      const _token1    = jwt.generate(_options1);
      const _token2    = jwt.generate(_options2);
      const _badToken3 = jwt.generate(_options3);
      const _tokens = ['Bearer ' + _token1, 'Bearer ' + _token2, 'Bearer ' + _badToken3];
      const _nbTokenToVerify = [0, 0, 0];
      let _nbTokenVerifiedOk = 0;
      let _nbTokenVerifiedKo = 0;
      function getPublicKeyFn (req, res, payload, callback) {
        return setTimeout(() => {
          callback(null, getECDHPublic());
        }, 100);
      }
      const _middlewareFn = jwt.verifyHTTPHeaderFn(_options1.payload.serverId, getPublicKeyFn);
      const _req = { headers : { authorization : '' } };
      // pre-warm cache
      _req.headers.authorization = _tokens[0];
      _middlewareFn(_req, {}, function () {
        _req.headers.authorization = _tokens[1];
        _middlewareFn(_req, {}, function () {
          _req.headers.authorization = _tokens[2];
          _middlewareFn(_req, {}, function () {
            const _start = process.hrtime();
            while (_iteration < _nbIteration) {
              _iteration++;
              const _selectedToken = parseInt(Math.random() * 3, 10);
              _nbTokenToVerify[_selectedToken]++;
              const _req = { headers : { authorization : _tokens[_selectedToken] } };
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
              const _elapsed = getDurationInUS(_start);
              const _tokenPerSecond = parseInt(_iteration / (_elapsed / 1e6), 10);
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
    it('should accepts headers with lower case. req.jwtPayload should still be defined if cache is used', done => {
      const options = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 10,
        },
        privKey : getECDHPriv()
      };
      const _token = jwt.generate(options);

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(options.payload.clientId);
        should(payload.aud).equal(options.payload.serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, getECDHPublic());
        }, 0);
      }
      const _middlewareFn = jwt.verifyHTTPHeaderFn(options.payload.serverId, getPublicKeyFn);
      const _req = {
        headers : {
          authorization : 'bearer ' + _token
        }
      };
      function next (err) {
        should(err).be.undefined();
        should(_req.jwtPayload.iss).equal(options.payload.clientId);
        should(_req.jwtPayload.aud).equal(options.payload.serverId);
        should(_req.jwtPayload.exp).be.approximately((Date.now() / 1000) + options.payload.expiresIn, 10);
        delete _req.jwtPayload;
        _middlewareFn(_req, {}, () => {
          // _req.jwtPayload should be defined even if cache is used (second call)
          should(_req.jwtPayload.iss).equal(options.payload.clientId);
          should(_req.jwtPayload.aud).equal(options.payload.serverId);
          done();
        });
      }
      _middlewareFn(_req, {}, next);
    });
    it('should accepts token in cookies', done => {
      const options = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 10,
        },
        privKey : getECDHPriv()
      };
      const _token = jwt.generate(options);

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(options.payload.clientId);
        should(payload.aud).equal(options.payload.serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, getECDHPublic());
        }, 0);
      }
      const _middlewareFn = jwt.verifyHTTPHeaderFn(options.payload.serverId, getPublicKeyFn);
      const _req = {
        headers : {
          cookie : 'access_token=' + _token
        }
      };
      function next (err) {
        should(err).be.undefined();
        should(_req.jwtPayload.iss).equal(options.payload.clientId);
        should(_req.jwtPayload.aud).equal(options.payload.serverId);
        should(_req.jwtPayload.exp).be.approximately((Date.now() / 1000) + options.payload.expiresIn, 10);
        delete _req.jwtPayload;
        _middlewareFn(_req, {}, () => {
          // _req.jwtPayload should be defined even if cache is used (second call)
          should(_req.jwtPayload.iss).equal(options.payload.clientId);
          should(_req.jwtPayload.aud).equal(options.payload.serverId);
          done();
        });
      }
      _middlewareFn(_req, {}, next);
    });
    it('should return an error if http Authorization header is empty', done => {
      const _clientId = '123';
      const _serverId = 'service1';

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, getECDHPublic());
        }, 0);
      }
      const _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      const _req = {
        headers : {}
      };
      function next (err) {
        should(err + '').be.equal('Error: No JSON Web Token detected in Authorization header or Cookie. Format is "Authorization: jwt" or "Cookie: access_token=jwt"');
        done();
      }
      _middlewareFn(_req, {}, next);
    });
    it('should return an error if http Authorization header is undefined', function (done) {
      const _clientId = '123';
      const _serverId = 'service1';
      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, getECDHPublic());
        }, 0);
      }
      const _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      const _req = {};
      function next (err) {
        should(err + '').be.equal('Error: JSON Web Token - No HTTP header detected');
        done();
      }
      _middlewareFn(_req, {}, next);
    });
    it('should return an error if http Authorization header is null (it should not crash)', function (done) {
      const _clientId = '123';
      const _serverId = 'service1';

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(_clientId);
        should(payload.aud).equal(_serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, getECDHPublic());
        }, 0);
      }
      const _middlewareFn = jwt.verifyHTTPHeaderFn(_serverId, getPublicKeyFn);
      const _req = {
        headers : null
      };
      function next (err) {
        should(err + '').be.equal('Error: JSON Web Token - No HTTP header detected');
        done();
      }
      _middlewareFn(_req, {}, next);
    });
    it('should return an error if the token is expired. And it should be faster the second time (cache)', function (done) {
      const options = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 1,
        },
        privKey : getECDHPriv()
      };
      const _token = jwt.generate(options);
      let _start = 0;

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(options.payload.clientId);
        should(payload.aud).equal(options.payload.serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, getECDHPublic());
        }, 0);
      }
      const _middlewareFn = jwt.verifyHTTPHeaderFn(options.payload.serverId, getPublicKeyFn);
      const _req = {
        headers : {
          Authorization : 'Bearer ' + _token
        }
      };
      function next (err) {
        should(err + '').be.equal('Error: JSON Web Token expired');
        _start = process.hrtime();
        // should return the same error both (cache is used if asked two times)
        _middlewareFn(_req, {}, () => {
          _middlewareFn(_req, {}, () => {
            _middlewareFn(_req, {}, (err) => {
              nextAndEnd(err);
            });
          });
        });
      }
      function nextAndEnd (err) {
        should(err + '').be.equal('Error: JSON Web Token expired');
        const _elapsed = getDurationInUS(_start);
        should(_elapsed).be.below(500);
        done();
      }
      setTimeout(() => {
        _middlewareFn(_req, {}, next);
      }, 1200);
    });
    it('should return an error if the token is expired, even is it cached (NOT THE SAME TEST AS ABOVE)', function (done) {
      const options = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 1,
        },
        privKey : getECDHPriv()
      };
      const _token = jwt.generate(options);

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(options.payload.clientId);
        should(payload.aud).equal(options.payload.serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, getECDHPublic());
        }, 0);
      }
      const _middlewareFn = jwt.verifyHTTPHeaderFn(options.payload.serverId, getPublicKeyFn);
      const _req = {
        headers : {
          Authorization : 'Bearer ' + _token
        }
      };
      function next (err) {
        should(err + '').be.equal('Error: JSON Web Token expired');
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
      const options = {
        payload : {
          clientId  : '123',
          serverId  : 'service1',
          expiresIn : 10,
        },
        privKey : getECDHPriv()
      };
      const _token = jwt.generate(options);

      function getPublicKeyFn (req, res, payload, callback) {
        should(payload.iss).equal(options.payload.clientId);
        should(payload.aud).equal(options.payload.serverId);
        // make it asynchrone
        return setTimeout(() => {
          callback(null, getECDHPublic());
        }, 0);
      }
      const _middlewareFn = jwt.verifyHTTPHeaderFn('otherServer', getPublicKeyFn);
      const _req = {
        headers : {
          Authorization : 'Bearer ' + _token
        }
      };
      function next (err) {
        should(err + '').be.equal('Error: Invalid JSON Web Token audience');
        done();
      }
      _middlewareFn(_req, {}, next);
    });
  });
});

// prime256v1
function getECDHPublic256 () {
  return '-----BEGIN PUBLIC KEY-----\n'
    + 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVzKI2nSLwOfDjaWsdfkGUuGFEeSh\n'
    + 'Y9RtMeCj7PBF2p3vFE1QrEBCNkKqTyK0fhpHiVhiuOWwzNpKQGx1/X2rSg==\n'
    + '-----END PUBLIC KEY-----\n'
  ;
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

function getRSAPriv () {
  return `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAu9R5q2IFmJp2RP+FTeu5Ka0jRAswiI79ZWQT/3BlLwAuBZUJ
zX2eNzZZJRDOqhyJM/LsOi95Tp9zHjLQQ/pIifdwzbI2qQgtxHjPWW10wttcJY4y
0/FVcVF4xd3GW6oUrXVHiMY4IBU+yrJAdOfafG5LwN9lZvrDuYNB3X8Ia6j+aPzv
gzpSc/9NVenLjNhO6wH/cS4/YlWqLRyku3GtMSRTV5og3rozGJy0ItUL5akbHlLU
hrZ1d59YtJb5972Mn6oFB+FvstKZnxhNoHq0zo9quQcyhefIjU/skLiXrptTUbsY
tiUz3b2ggXVDDU3166D0R4UrKM9EDX9KAbPLrwIDAQABAoIBAFUFkUuYM8NHi+ig
p1VFsgug8TkwPXhbDW2zVvAGDu8vDCX/uC+5wH/qjICgMoRDJYIL4I1YBvelaoUN
aEOVC/fTt06M8HwkFR99thIbX0KC7Bud2fkhIVWJlPsv78V3YCPCVi6d1zMCmulC
tbWVa8tuW8EC/lIWibk0JoDeK1Abp+HuTtXPwzH7eNYBV1T4YelGSa+wVbX4kUyl
ngbjrSNN6ang9mCtaF0IL0W6mxbBWz6UpzL8eP1OK3pn97T2Z6t8pmPeeQL2NG6Y
lhVRdtCjkiB0xDPZ3gGRL8T50CecDhiGDWEXILfx+ufXMx4m14dHiBj1JyWL7RGj
znzVNhUCgYEA9ASANnAsKNjB4TM8GSXddo5zRWnOohv0Uf8lHaGikBwV4jTuRsiS
oHnBlNELx1L+1Vz/u3R41K8N2sqvzkHeLwdvpbfYDdPB8Vsie6dka4tfqbDHVVKG
uLrABMhLkJ/Gwlh1+OjShfSO9G/ILrypBFCV0L9zNOkMakv9nc4QmcsCgYEAxQ2m
kvB9IlsABlL+bGalUZV2oQVDbUHoYbWELefcA7l3WggXV/2SImk1vRgmhTfUt4lP
oXkbmzO6jrTFdVsLpr1ambaFvDXb91XhHK8mDR0TOgxsO0ZWccKG2Z/uVgKoEyrG
x5/BKkeDue8YuG7h8udBQGA6y8o52v97EeiN6S0CgYAVJCavkLxitZTmm/fC/gLX
+LOH+gjLBrz+NarTjGN3NNe4h3l1bH83pBTffdUVad1mQu5tIUQuuRPsNs9QgWhs
jqpfozP2zrfo30p3iCMtJiAdpZE/lSzS6Gsmfuv9Fbq0r9FYxWMn8+5Gw0CGvBWw
qAKy2UNz/BT1SKwqdeX+TQKBgQC7KgQVfSbeAuE7IIlYHQbZPsW2m3E3zWoTpH0v
vRJU10xtz1Gc2dR7qsLIILA1yJna2ikwjf+SoseH1FvY4+llLmVnqt3LrryHaKKw
xAu4WO1yLWp/wodI9iNvgWC3gT5zNiYoZazro5GSgW9RfsBOHyjzJHO0LRhW0mLq
16Ay4QKBgQCZM8h1t9Zuvc/IHE1YdGfPlijlWwsXBPwWxY73LOOKsdA4K0CZfMh4
GcTIGP61YKBDS/vb9W1+URM2As/6DpMHQqRTnsKzsQS76a7iH10vdxKJCCeeja1X
3aFRpOICg8c9T89RdvC/aBnltqYAKuyaZbo/yWnEzC75ZhIMESUD2A==
-----END RSA PRIVATE KEY-----`;
}

function getRSAPub () {
  return `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAu9R5q2IFmJp2RP+FTeu5Ka0jRAswiI79ZWQT/3BlLwAuBZUJzX2e
NzZZJRDOqhyJM/LsOi95Tp9zHjLQQ/pIifdwzbI2qQgtxHjPWW10wttcJY4y0/FV
cVF4xd3GW6oUrXVHiMY4IBU+yrJAdOfafG5LwN9lZvrDuYNB3X8Ia6j+aPzvgzpS
c/9NVenLjNhO6wH/cS4/YlWqLRyku3GtMSRTV5og3rozGJy0ItUL5akbHlLUhrZ1
d59YtJb5972Mn6oFB+FvstKZnxhNoHq0zo9quQcyhefIjU/skLiXrptTUbsYtiUz
3b2ggXVDDU3166D0R4UrKM9EDX9KAbPLrwIDAQAB
-----END RSA PUBLIC KEY-----`;
}

function getPayload (token, encoded) {
  const _segments = token.split('.');
  const _payloadSeg = _segments[1];
  let _payload = JSON.parse(base64urlDecode(_payloadSeg));
  if (encoded) {
    _payload = _payloadSeg;
  }
  return _payload;
}

function getHeader (token, encoded) {
  const _segments = token.split('.');
  const _headerSeg = _segments[0];
  let _header = JSON.parse(base64urlDecode(_headerSeg));
  if (encoded) {
    _header = _headerSeg;
  }
  return _header;
}

function base64urlDecode (str) {
  return new Buffer(base64urlUnescape(str), 'base64').toString();
}

function base64urlUnescape (str) {
  str += new Array(5 - str.length % 4).join('=');
  return str.replace(/-/g, '+').replace(/_/g, '/');
}

function getDurationInUS (time) {
  const _interval = process.hrtime(time);
  return _interval[0] * 1e6 + parseInt(_interval[1] / 1e3, 10);
}

