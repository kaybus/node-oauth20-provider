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
            // oauth2.model.user.fetchById(req, oauth2.model.refreshToken.getUserId(refreshToken), function(err, obj) {
            //     if (err)
            //         cb(new error.serverError('Failed to call user::fetchById method'));
            //     else if (!obj)
            //         cb(new error.invalidClient('User not found'));
            //     else {
            //         oauth2.logger.debug('User fetched: ', obj);
            //         user = obj;
            //         cb();
            //     }
            // });
            user = null;
            cb();
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
        // Issue new one.
        function(cb) {
            /*To support multiple login, we are always issuing new access token in the refresh token flow.*/
            accessTokenValue = oauth2.model.accessToken.generateToken();
            var cloneOfRefreshToken = JSON.parse(JSON.stringify(refreshToken));
            oauth2.model.accessToken.save(req, accessTokenValue, cloneOfRefreshToken, oauth2.model.client.getId(client), oauth2.model.refreshToken.getScope(refreshToken), accessTokenTtl, function(err) {
                if (err)
                    cb(new error.serverError('Failed to call accessToken::save method'));
                else {
                    oauth2.logger.debug('Access token saved: ', accessTokenValue);
                    cb();
                }
            });
        },
        //Refresh the refreshToken
        function(cb) {
          if(refreshToken) {
            oauth2.model.refreshToken.refresh(req, refreshToken['Token'], null, oauth2.model.client.getId(client), function(err) {
              if (err)
                cb(new error.serverError('Failed to refresh refreshToken'));
              else {
                oauth2.logger.debug('Refresh token refreshed: ', refreshToken['Token']);
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
                access_token: accessTokenValue,
                user_id: refreshToken.UserID,
                account_id: refreshToken.AccountID,
                result_code: "Success"
            };
            if(accessTokenTtl > 0)
                token.expires_in = accessTokenTtl;
            pCb(null, token);
        }
    });
};