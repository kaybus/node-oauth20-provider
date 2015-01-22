/**
 * Created by sumukhavadhani on 12/3/14.
 */

var
  async = require('async'),
  response = require('./../../util/response.js'),
  error = require('./../../error');

module.exports = function(req, oauth2, client, username, scope, pCb) {

  // Define variables
  var scope,
    user,
    accessTokenValue,
    accessTokenTtl;

  async.waterfall([
      // Check username parameter
      function(cb) {
        if (!username)
          return cb(new error.invalidRequest('Username is mandatory for guest extension grant type'));
        oauth2.logger.debug('Username parameter check passed: ', username);

        cb();
      },
      // Parse and check scope against supported and client available scopes
      function(cb) {
        scope = oauth2.model.client.transformScope(scope);
        scope = oauth2.model.client.checkScope(client, scope);
        if (!scope)
          cb(new error.invalidScope('Invalid scope for the client'));
        else {
          oauth2.logger.debug('Scope check passed: ', scope);
          cb();
        }
      },
      // Fetch user
      function(cb) {
        oauth2.model.user.fetchByUsername(req, username, function(err, obj) {
          if (err)
            cb(new error.serverError('Failed to call user::fetchByUsername method'));
          else if (!obj)
            cb(new error.invalidClient('User not found'));
          else {
            oauth2.logger.debug('User fetched: ', obj);
            user = obj;
            cb();
          }
        });
      },
      //Get accessToken ttl based on the req and the client
      function(cb) {
        oauth2.model.accessToken.getTTL(req, user, client, function(err, ttl) {
          if(err)
            cb(new error.serverError('Failed to call accessToken::getTTL method'));
          else {
            accessTokenTtl = ttl;
            cb();
          }
        });
      },
      // Generate new accessToken and save it
      function(cb) {
        accessTokenValue = oauth2.model.accessToken.generateToken();
        oauth2.model.accessToken.save(req, accessTokenValue, oauth2.model.user.getId(user), oauth2.model.client.getId(client), scope, accessTokenTtl, function(err) {
          if (err)
            cb(new error.serverError('Failed to call accessToken::save method'));
          else {
            oauth2.logger.debug('Access token saved: ', accessTokenValue);
            cb();
          }
        });
      }
    ],
    function(err) {
      if (err) pCb(err);
      else {
        var token = {
          token_type: "bearer",
          access_token: accessTokenValue
        };
        if(accessTokenTtl > 0)
          token.expires_in = accessTokenTtl;
        pCb(null, token);
      }
    });
};
