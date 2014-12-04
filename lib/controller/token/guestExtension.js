/**
 * Created by sumukhavadhani on 12/3/14.
 */

var
  async = require('async'),
  response = require('./../../util/response.js'),
  error = require('./../../error');

module.exports = function(req, oauth2, client, scope, pCb) {

  // Define variables
  var scope,
    accessTokenValue,
    accessTokenTtl;

  async.waterfall([
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
      // Verify share token for the client
      function(cb) {
        oauth2.model.client.validateGuestExtensionID(req, client, function(status, err) {
          if(err)
            cb(new error.serverError('Failed to call client::validateGuestExtensionID method'));
          else {
            if(!status) {
              cb(new error.invalidGrant('Invalid Share token'));
            }
            cb();
          }
        });
      },
      //Get accessToken ttl based on the req and the client
      function(cb) {
        oauth2.model.accessToken.getTTL(req, client, function(err, ttl) {
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
        oauth2.model.accessToken.save(req, accessTokenValue, null, oauth2.model.client.getId(client), scope, accessTokenTtl, function(err) {
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
