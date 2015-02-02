var
    async = require('async'),
    error = require('./../../error');

module.exports = function(req, oauth2, client, refresh_token, scope, pCb) {
    // Define variables
    var user,
        refreshToken,
        accessToken,
        accessTokenValue,
        accessTokenTtl;

    async.waterfall([
        // Check refresh_token parameter
        function(cb) {
            if (!refresh_token)
                return cb(new error.invalidRequest('RefreshToken is mandatory for refresh_token grant type'));
            oauth2.logger.debug('RefreshToken parameter check passed: ', refresh_token);

            cb();
        },
        // Standard is really weird here, do not check scope, just fill it from refreshToken
        // function(cb) {CHECK SCOPE PARAMETER FUNCTION OMITTED},
        // Fetch refreshToken
        function(cb) {
            oauth2.model.refreshToken.fetchByToken(refresh_token, function(err, obj) {
                if (err)
                    cb(new error.serverError('Failed to call refreshToken::fetchByToken method'));
                else if (!obj)
                    cb(new error.invalidGrant('Refresh token not found'));
                else if (obj.clientId != oauth2.model.client.getId(client)) {
                    oauth2.logger.warn('Client id "' + oauth2.model.client.getId(client) + '" tried to fetch client id "' + obj.clientId + '" refresh token');
                    cb(new error.invalidGrant('Refresh token not found'));
                }
                else {
                    oauth2.logger.debug('RefreshToken fetched: ', obj);
                    refreshToken = obj;
                    cb();
                }
            });
        },
        // Fetch user
        function(cb) {
            oauth2.model.user.fetchById(req, oauth2.model.refreshToken.getUserId(refreshToken), function(err, obj) {
                if (err)
                    cb(new error.serverError('Failed to call user::fetchById method'));
                else if (!obj)
                    cb(new error.invalidClient('User not found'));
                else {
                    oauth2.logger.debug('User fetched: ', obj);
                    user = obj;
                    cb();
                }
            });
        },
        // Fetch issued access token (if it is already created and still active)
        function(cb) {
            oauth2.model.accessToken.fetchByUserIdClientId(oauth2.model.user.getId(user), oauth2.model.client.getId(client), function(err, obj) {
                if (err)
                    cb(new error.serverError('Failed to call accessToken::fetchByUserIdClientId'));
                else if (!obj) cb();
                else {
                    accessToken = obj;
                    oauth2.logger.debug('Fetched issued accessToken: ', obj);
                    cb();
                };
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
        // Issue new one (if needed)
        function(cb) {
            // No need if it already exists and valid
            if (accessToken) {
                accessTokenValue = oauth2.model.accessToken.getToken(accessToken);
                cb();
            }
            else {
                accessTokenValue = oauth2.model.accessToken.generateToken();
                oauth2.model.accessToken.save(req, accessTokenValue, oauth2.model.user.getId(user), oauth2.model.client.getId(client), oauth2.model.refreshToken.getScope(refreshToken), accessTokenTtl, function(err) {
                    if (err)
                        cb(new error.serverError('Failed to call accessToken::save method'));
                    else {
                        oauth2.logger.debug('Access token saved: ', accessTokenValue);
                        cb();
                    }
                });
            }
        },
        //Refresh the refreshToken
        function(cb) {
          if(refreshToken) {
            oauth2.model.refreshToken.refresh(req, refreshToken['token'], oauth2.model.user.getId(user), oauth2.model.client.getId(client), function(err) {
              if (err)
                cb(new error.serverError('Failed to refresh refreshToken'));
              else {
                oauth2.logger.debug('Refresh token refreshed: ', refreshToken['token']);
                cb();
              }
            });
          } else {
            cb(new error.serverError('Failed to call refreshToken::refresh method'));
          }
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