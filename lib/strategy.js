var passport = require('passport-strategy')
  , util = require('util');


function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) throw new Error('OAuth 2.0 public client strategy requires a verify function');
  
  passport.Strategy.call(this);
  this.name = 'oauth2-client-public';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req) {
  if (!req.body || !req.body['client_id']) {
    return this.fail();
  }
  if (req.body['client_secret']) {
    return this.fail();
  }
  
  var clientId = req.body['client_id'];

  var self = this;

  function verified(err, client, info) {
    if (err) { return self.error(err); }
    if (!client) { return self.fail(info); }
    
    info = info || {};
    info.unauthenticated = true;
    self.success(client, info);
  }

  if (self._passReqToCallback) {
    this._verify(req, clientId, verified);
  } else {
    this._verify(clientId, verified);
  }
};


module.exports = Strategy;
